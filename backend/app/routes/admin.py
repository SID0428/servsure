import hashlib
import hmac
import html
import json
import os
import re
import secrets
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.db.models import (
    CompanyOnboardingModel, BranchOnboardingModel, TechnicianOnboardingModel,
    UserModel, CompanyBranchModel,
    TechnicianModel, BranchTechnicianModel, ApplianceModel, ServiceRequestModel,
    JobCardModel, CompanyApplianceCatalogModel
)
from app.db.session import get_db
from app.schemas import (
    AccessTogglePayload, CompanyCreate, CompanyCredentialsEmail, CompanyOtpVerify,
    CompanyPasswordSetup, CompanyBranchCreate, PreaddedBranchConfigure
)
from app.security import get_authenticated_user, revoke_all_user_sessions
from app.email_service import send_brevo_email

router = APIRouter(prefix="/api/admin", tags=["admin"])
onboarding_router = APIRouter(prefix="/api/onboarding", tags=["company onboarding"])


def require_admin(request: Request, db: Session) -> UserModel:
    user = get_authenticated_user(request, db)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    return user


def make_password_hash(password: str) -> str:
    rounds, salt = 310_000, secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds).hex()
    return f"pbkdf2_sha256${rounds}${salt.hex()}${digest}"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def company_payload(user: UserModel, onboarding: CompanyOnboardingModel | None = None) -> dict:
    created_at_val = None
    if getattr(user, "created_at", None):
        iso_str = user.created_at.isoformat()
        created_at_val = iso_str if iso_str.endswith("Z") else f"{iso_str}Z"
    return {
        "id": user.id, "name": user.name, "email": user.email, "phone": user.phone,
        "address": user.address, "role": user.role,
        "is_active": getattr(user, "is_active", False if (onboarding and not onboarding.password_set_at) else True),
        "password_set": bool(onboarding and onboarding.password_set_at),
        "password_set_at": f"{onboarding.password_set_at.isoformat()}Z" if onboarding and onboarding.password_set_at else None,
        "created_at": created_at_val,
    }


def issue_invite(company: UserModel, onboarding: CompanyOnboardingModel) -> str:
    token = secrets.token_urlsafe(32)
    onboarding.invite_token_hash = digest(token)
    onboarding.invite_expires_at = datetime.utcnow() + timedelta(hours=48)
    onboarding.pending_password_hash = None
    onboarding.otp_hash = None
    onboarding.otp_expires_at = None
    frontend_url = os.getenv("FRONTEND_BASE_URL", "https://servsure.vercel.app").rstrip("/")
    link = f"{frontend_url}/company-setup.html?token={token}"
    safe_name = html.escape(company.name)
    safe_email = html.escape(company.email)
    send_brevo_email(
        company.email, company.name, "Set up your ServSure company admin account",
        f"Hello {company.name},\n\nYour company has been added to ServSure. To set up your company admin password, verify your registered email and follow this link (valid for 48 hours):\n{link}\n\nYour registered login email is {company.email}.",
        f"<p>Hello {safe_name},</p><p>Your company has been added to ServSure. Use the link below to verify your registered email and create your company admin password. This link expires in 48 hours.</p><p><a href=\"{link}\">Create your ServSure password</a></p><p>Registered login email: <strong>{safe_email}</strong></p>",
    )
    return link


@router.get("/companies")
def list_companies(request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    rows = db.query(UserModel).filter(UserModel.role == "company").order_by(UserModel.name).all()
    onboarding = {item.company_id: item for item in db.query(CompanyOnboardingModel).all()}
    return [company_payload(user, onboarding.get(user.id)) for user in rows]


@router.put("/companies/{company_id}/access")
def toggle_company_access(company_id: str, payload: AccessTogglePayload, request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    company = db.query(UserModel).filter(UserModel.id == company_id, UserModel.role == "company").first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    company.is_active = payload.is_active

    # If disabling company, immediately revoke active sessions for company, its branches, and technicians
    if not payload.is_active:
        revoke_all_user_sessions(company.id, db)
        branches = db.query(CompanyBranchModel).filter(CompanyBranchModel.company_id == company.id).all()
        for b in branches:
            revoke_all_user_sessions(b.id, db)
            b_user = db.query(UserModel).filter((UserModel.id == b.id) | (UserModel.email == b.email)).first()
            if b_user:
                revoke_all_user_sessions(b_user.id, db)
            tech_links = db.query(BranchTechnicianModel).filter(BranchTechnicianModel.branch_id == b.id).all()
            for bt in tech_links:
                revoke_all_user_sessions(bt.technician_id, db)

    db.commit()
    db.refresh(company)
    onboarding = db.query(CompanyOnboardingModel).filter_by(company_id=company.id).first()
    return {
        "status": "success",
        "message": f"Company access {'enabled' if payload.is_active else 'disabled'} successfully",
        "company": company_payload(company, onboarding)
    }


@router.get("/companies/{company_id}")
def get_company_details(company_id: str, request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    company = db.query(UserModel).filter(UserModel.id == company_id, UserModel.role == "company").first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    onboarding = db.query(CompanyOnboardingModel).filter_by(company_id=company.id).first()

    branches = (
        db.query(CompanyBranchModel)
        .filter(CompanyBranchModel.company_id == company.id)
        .order_by(CompanyBranchModel.branch_name)
        .all()
    )
    branch_ids = [b.id for b in branches]

    branch_tech_links = (
        db.query(BranchTechnicianModel)
        .filter(BranchTechnicianModel.branch_id.in_(branch_ids))
        .all()
    ) if branch_ids else []
    tech_ids = [bt.technician_id for bt in branch_tech_links]

    technicians = (
        db.query(TechnicianModel)
        .filter(TechnicianModel.id.in_(tech_ids))
        .all()
    ) if tech_ids else []

    if not technicians and branches:
        branch_names = [b.branch_name for b in branches]
        technicians = (
            db.query(TechnicianModel)
            .filter(
                or_(
                    TechnicianModel.company_branch.in_(branch_names),
                    TechnicianModel.company_branch.ilike(f"%{company.name}%")
                )
            )
            .all()
        )

    products = (
        db.query(ApplianceModel)
        .filter(
            or_(
                ApplianceModel.company_id == company.id,
                ApplianceModel.brand.ilike(company.name.strip())
            )
        )
        .all()
    )

    services = (
        db.query(ServiceRequestModel)
        .filter(
            or_(
                ServiceRequestModel.company_id == company.id,
                ServiceRequestModel.brand.ilike(company.name.strip())
            )
        )
        .order_by(ServiceRequestModel.created_at.desc())
        .all()
    )

    ongoing_services = [s for s in services if s.status_badge in ("In Progress", "Scheduled") or s.status not in ("Completed", "Cancelled")]
    completed_services = [s for s in services if s.status_badge == "Completed" or s.status == "Completed"]
    pending_services = [s for s in services if not s.technician_id]

    tech_map = {t.id: t.name for t in technicians}

    return {
        "company": company_payload(company, onboarding),
        "stats": {
            "total_branches": len(branches),
            "total_technicians": len(technicians),
            "total_products": len(products),
            "total_services": len(services),
            "ongoing_services": len(ongoing_services),
            "completed_services": len(completed_services),
            "pending_services": len(pending_services),
        },
        "branches": [
            {
                "id": b.id,
                "branch_name": b.branch_name,
                "manager_name": b.manager_name,
                "email": b.email,
                "mobile": b.mobile,
                "address": b.address,
                "pincode": b.pincode,
                "technicians_count": sum(1 for bt in branch_tech_links if bt.branch_id == b.id)
            }
            for b in branches
        ],
        "technicians": [
            {
                "id": t.id,
                "name": t.name,
                "title": t.title,
                "company_branch": t.company_branch,
                "rating": t.rating,
                "total_jobs": t.total_jobs,
                "phone": t.phone,
                "avatar": t.avatar,
                "is_verified": t.is_verified,
            }
            for t in technicians
        ],
        "products": [
            {
                "id": p.id,
                "brand": p.brand,
                "category": p.category,
                "model_no": p.model_no,
                "serial_no": p.serial_no or "Standard",
                "warranty_status": p.warranty_status or "Active",
                "registered_on": p.registered_on,
                "customer_id": p.user_id,
            }
            for p in products
        ],
        "services": [
            {
                "id": s.id,
                "customer_name": s.customer_name,
                "customer_phone": s.customer_phone,
                "customer_address": s.customer_address,
                "appliance_name": s.appliance_name,
                "issue": s.issue,
                "priority": s.priority,
                "status": s.status,
                "status_badge": s.status_badge,
                "appointment_date": s.appointment_date,
                "appointment_slot": s.appointment_slot,
                "technician_id": s.technician_id,
                "technician_name": tech_map.get(s.technician_id, "Unassigned"),
                "pincode": s.pincode,
            }
            for s in services
        ]
    }


@router.get("/directory/{role}")
def list_directory(role: str, request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    if role not in {"branch", "technician", "customer"}:
        raise HTTPException(status_code=404, detail="Directory not found")

    if role == "branch":
        branches = db.query(CompanyBranchModel).order_by(CompanyBranchModel.branch_name).all()
        companies_by_id = {u.id: u for u in db.query(UserModel).filter(UserModel.role == "company").all()}
        branch_users_by_id = {u.id: u for u in db.query(UserModel).filter(UserModel.role == "branch").all()}
        branch_users_by_email = {u.email.lower(): u for u in db.query(UserModel).filter(UserModel.role == "branch").all()}
        branch_onboarding_map = {item.branch_id: item for item in db.query(BranchOnboardingModel).all()}

        result = []
        for b in branches:
            company = companies_by_id.get(b.company_id)
            b_user = branch_users_by_id.get(b.id) or branch_users_by_email.get(b.email.lower())
            onb = branch_onboarding_map.get(b.id)
            pw_set = bool(onb and onb.password_set_at)
            pw_set_at = f"{onb.password_set_at.isoformat()}Z" if (onb and onb.password_set_at) else None
            created_at_val = f"{b.created_at.isoformat()}Z" if (b.created_at and not b.created_at.isoformat().endswith("Z")) else (b.created_at.isoformat() if b.created_at else None)
            
            branch_ids = [b.id]
            if b_user and b_user.id != b.id:
                branch_ids.append(b_user.id)

            tech_links = db.query(BranchTechnicianModel).filter(BranchTechnicianModel.branch_id.in_(branch_ids)).all()
            linked_tech_ids = [tl.technician_id for tl in tech_links]
            named_tech_ids = [
                t.id for t in db.query(TechnicianModel).filter(
                    TechnicianModel.company_branch.ilike(b.branch_name.strip())
                ).all()
            ] if b.branch_name else []
            assigned_tech_ids = list(set(linked_tech_ids + named_tech_ids))
            tech_count = len(assigned_tech_ids)

            job_filters = [ServiceRequestModel.branch_id.in_(branch_ids)]
            if assigned_tech_ids:
                job_filters.append(ServiceRequestModel.technician_id.in_(assigned_tech_ids))
            if b.pincode and len(b.pincode.strip()) == 6:
                job_filters.append(ServiceRequestModel.pincode == b.pincode.strip())

            jobs_query = db.query(ServiceRequestModel).filter(or_(*job_filters))
            jobs_count = jobs_query.count()
            ongoing_jobs = jobs_query.filter(ServiceRequestModel.status_badge != "Completed").count()

            result.append({
                "id": b.id,
                "branch_code": getattr(b, "branch_code", None) or f"BR-{b.id.replace('branch_', '')[:6].upper()}",
                "name": b.branch_name,
                "branch_name": b.branch_name,
                "manager_name": b.manager_name,
                "company_id": b.company_id,
                "company_name": company.name if company else ("Multi-Brand Local Dealer Hub" if getattr(b, "is_dealer_franchise", False) or getattr(b, "dealer_companies", None) else "ServSure Network"),
                "parent_company_name": company.name if company else None,
                "email": b.email,
                "phone": b.mobile,
                "mobile": b.mobile,
                "address": b.address,
                "pincode": b.pincode,
                "dealer_companies": getattr(b, "dealer_companies", None),
                "is_dealer_franchise": bool(getattr(b, "is_dealer_franchise", False)),
                "is_dual_registered": bool(getattr(b, "is_dual_registered", False) or getattr(b, "registration_mode", None) == "dual" or (b.company_id and company and company.role == "company" and (getattr(b, "is_dealer_franchise", False) or getattr(b, "dealer_companies", None)))),
                "registration_mode": getattr(b, "registration_mode", None) or ("dual" if bool(getattr(b, "is_dual_registered", False) or (b.company_id and company and company.role == "company" and (getattr(b, "is_dealer_franchise", False) or getattr(b, "dealer_companies", None)))) else ("individual" if getattr(b, "is_dealer_franchise", False) else "company")),
                "is_active": getattr(b_user, "is_active", False) if b_user else False,
                "password_set": pw_set,
                "password_set_at": pw_set_at,
                "created_at": created_at_val,
                "total_techs": tech_count,
                "total_jobs": jobs_count,
                "ongoing_jobs": ongoing_jobs,
                "role": "branch",
                "avatar": b.branch_name[:2].upper()
            })
        return result

    elif role == "technician":
        try:
            db.query(BranchTechnicianModel).filter(BranchTechnicianModel.technician_id.in_(["tech_1", "tech_2"])).delete(synchronize_session=False)
            db.query(TechnicianModel).filter(
                (TechnicianModel.id.in_(["tech_1", "tech_2"])) | 
                (TechnicianModel.name.in_(["Rahul Sharma", "Suresh Kumar"]))
            ).delete(synchronize_session=False)
            db.query(UserModel).filter(
                (UserModel.id.in_(["tech_1", "tech_2"])) | 
                (UserModel.email.in_(["rahul.sharma@crompton-service.com", "tech2@servora.com", "suresh.kumar@servsure.com"]))
            ).delete(synchronize_session=False)
            db.commit()
        except Exception:
            db.rollback()

        techs = db.query(TechnicianModel).filter(
            ~TechnicianModel.id.in_(["tech_1", "tech_2"]),
            ~TechnicianModel.name.in_(["Rahul Sharma", "Suresh Kumar"])
        ).order_by(TechnicianModel.name).all()
        bt_links = {l.technician_id: l for l in db.query(BranchTechnicianModel).all()}
        branches_by_id = {b.id: b for b in db.query(CompanyBranchModel).all()}
        companies_by_id = {u.id: u for u in db.query(UserModel).filter(UserModel.role == "company").all()}
        tech_users_by_id = {u.id: u for u in db.query(UserModel).filter(UserModel.role == "technician").all()}
        tech_users_by_phone = {u.phone: u for u in db.query(UserModel).filter(UserModel.role == "technician").all()}
        tech_onboarding_map = {item.technician_id: item for item in db.query(TechnicianOnboardingModel).all()}

        result = []
        for t in techs:
            link = bt_links.get(t.id)
            branch = branches_by_id.get(link.branch_id) if link else None
            company = companies_by_id.get(branch.company_id) if branch else None
            t_user = tech_users_by_id.get(t.id) or tech_users_by_phone.get(t.phone)
            onb = tech_onboarding_map.get(t.id)
            pw_set = bool(onb and onb.password_set_at)
            pw_set_at = f"{onb.password_set_at.isoformat()}Z" if (onb and onb.password_set_at) else None
            raw_created = (link.created_at if link else None) or (getattr(t_user, "created_at", None) if t_user else None)
            created_at_val = f"{raw_created.isoformat()}Z" if (raw_created and not raw_created.isoformat().endswith("Z")) else (raw_created.isoformat() if raw_created else None)

            completed_jobs = db.query(ServiceRequestModel).filter(
                ServiceRequestModel.technician_id == t.id,
                ServiceRequestModel.status_badge == "Completed"
            ).count()
            active_jobs = db.query(ServiceRequestModel).filter(
                ServiceRequestModel.technician_id == t.id,
                ServiceRequestModel.status_badge != "Completed"
            ).count()
            total_jobs = completed_jobs + active_jobs
            if total_jobs == 0 and t.total_jobs:
                total_jobs = t.total_jobs

            result.append({
                "id": t.id,
                "name": t.name,
                "title": t.title or "Field Service Engineer",
                "phone": t.phone,
                "email": t_user.email if t_user else f"{t.name.lower().replace(' ', '.')}@servsure.com",
                "rating": round(t.rating or 5.0, 1),
                "total_jobs": total_jobs,
                "completed_jobs": completed_jobs,
                "active_jobs": active_jobs,
                "branch_id": branch.id if branch else None,
                "branch_name": branch.branch_name if branch else (t.company_branch or "Main Service Center"),
                "company_id": company.id if company else None,
                "company_name": company.name if company else "ServSure Certified Partner",
                "address": (link.address if link else None) or (branch.address if branch else "Field Service Territory"),
                "pincode": (link.pincode if link else None) or (branch.pincode if branch else ""),
                "is_active": getattr(t_user, "is_active", False) if t_user else False,
                "is_verified": t.is_verified,
                "password_set": pw_set,
                "password_set_at": pw_set_at,
                "created_at": created_at_val,
                "role": "technician",
                "avatar": t.avatar or t.name[:2].upper()
            })
        return result

    elif role == "customer":
        customers = db.query(UserModel).filter(UserModel.role == "customer").order_by(UserModel.name).all()
        result = []
        for c in customers:
            appliances_cnt = db.query(ApplianceModel).filter(ApplianceModel.user_id == c.id).count()
            total_reqs = db.query(ServiceRequestModel).filter(ServiceRequestModel.customer_id == c.id).count()
            ongoing_reqs = db.query(ServiceRequestModel).filter(
                ServiceRequestModel.customer_id == c.id,
                ServiceRequestModel.status_badge != "Completed"
            ).count()
            completed_reqs = db.query(ServiceRequestModel).filter(
                ServiceRequestModel.customer_id == c.id,
                ServiceRequestModel.status_badge == "Completed"
            ).count()
            created_at_val = f"{c.created_at.isoformat()}Z" if (getattr(c, "created_at", None) and not c.created_at.isoformat().endswith("Z")) else (c.created_at.isoformat() if getattr(c, "created_at", None) else None)

            result.append({
                "id": c.id,
                "name": c.name,
                "email": c.email,
                "phone": c.phone,
                "address": c.address or "Address not provided",
                "appliances_count": appliances_cnt,
                "total_requests": total_reqs,
                "ongoing_requests": ongoing_reqs,
                "completed_requests": completed_reqs,
                "is_active": c.is_active,
                "created_at": created_at_val,
                "role": "customer",
                "avatar": c.name[:2].upper()
            })
        return result


def is_generic_title(title: str | None, brand: str | None = "", category: str | None = "") -> bool:
    if not title or not title.strip():
        return True
    t = title.strip().lower()
    b = (brand or "").strip().lower()
    c = (category or "").strip().lower()
    if t in ("other", "appliance", "home appliance", "service request", "unknown"):
        return True
    if b and (t == b or t == f"{b} other" or t == f"{b} appliance" or t == f"{b} home appliance" or t.endswith(" other") or t.endswith(" appliance")):
        return True
    if b and c and c == "other" and t in (f"{b} {c}", f"{b} other", f"{b} appliance"):
        return True
    return False


def resolve_clean_appliance_name(app_obj, catalog_items=None, service_requests=None) -> str:
    name = (getattr(app_obj, "appliance_name", None) or "").strip()
    brand = (getattr(app_obj, "brand", None) or "").strip()
    category = (getattr(app_obj, "category", None) or "").strip()
    model = (getattr(app_obj, "model_no", None) or "").strip()

    if name and not is_generic_title(name, brand, category):
        return name

    # 1. Search in catalog_items
    if catalog_items:
        # A) Match model number inside model_numbers JSON/list
        if model:
            for ci in catalog_items:
                try:
                    m_list = json.loads(ci.model_numbers) if ci.model_numbers else []
                except Exception:
                    m_list = [m.strip() for m in str(ci.model_numbers or "").split(",") if m.strip()]
                if any(m.strip().lower() == model.lower() for m in m_list):
                    if ci.appliance_name and not is_generic_title(ci.appliance_name, brand, category):
                        return ci.appliance_name
                    if ci.category and ci.category.lower() != "other":
                        return f"{brand or ci.brand} {ci.category}".strip()

        # B) Match company/brand + category
        for ci in catalog_items:
            ci_brand = (ci.brand or "").strip().lower()
            ci_comp = getattr(ci, "company_id", None)
            comp_match = (ci_comp and ci_comp == getattr(app_obj, "company_id", None)) or (ci_brand and brand and ci_brand == brand.lower())
            if comp_match:
                if category and category.lower() != "other" and ci.category and ci.category.lower() == category.lower():
                    if ci.appliance_name and not is_generic_title(ci.appliance_name, brand, category):
                        return ci.appliance_name
                elif category and category.lower() == "other":
                    if ci.category and ci.category.lower() == "other" and ci.appliance_name and not is_generic_title(ci.appliance_name, brand, category):
                        return ci.appliance_name

    # 2. Search in service_requests
    if service_requests:
        app_id = getattr(app_obj, "id", None)
        for r in service_requests:
            if (app_id and getattr(r, "appliance_id", None) == app_id) or (model and getattr(r, "model_no", None) and r.model_no.lower() == model.lower()):
                r_name = (getattr(r, "appliance_name", None) or "").strip()
                if r_name and not is_generic_title(r_name, brand, category):
                    return r_name

    # 3. Check matched_policy_name
    matched_pol = getattr(app_obj, "matched_policy_name", None)
    if matched_pol:
        clean_pol = re.sub(r'(?i)\b(standard|warranty|policy|coverage|extended|fy\s*\d{2,4}[-\d]*)\b', '', matched_pol).strip()
        if clean_pol and not is_generic_title(clean_pol, brand, category):
            return f"{brand} {clean_pol}".strip() if brand and brand.lower() not in clean_pol.lower() else clean_pol

    # 4. Fallback to Brand + Category if Category is not "Other"
    if category and category.lower() != "other":
        return f"{brand} {category}".strip() if brand else category

    # 5. Catalog fallback for this brand/company
    if catalog_items:
        for ci in catalog_items:
            ci_brand = (ci.brand or "").strip().lower()
            ci_comp = getattr(ci, "company_id", None)
            if (ci_comp and ci_comp == getattr(app_obj, "company_id", None)) or (ci_brand and brand and ci_brand == brand.lower()):
                if ci.appliance_name and not is_generic_title(ci.appliance_name, brand, category):
                    return ci.appliance_name

    # 6. Fallback to existing name or Brand Appliance
    if name and name.strip():
        return name
    return f"{brand} Appliance".strip() if brand else "Home Appliance"


@router.get("/customers/{customer_id}")
def get_admin_customer_details(customer_id: str, request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    customer = db.query(UserModel).filter(UserModel.id == customer_id, UserModel.role == "customer").first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    appliances = db.query(ApplianceModel).filter(ApplianceModel.user_id == customer.id).order_by(ApplianceModel.registered_on.desc()).all()
    companies_by_id = {u.id: u for u in db.query(UserModel).filter(UserModel.role == "company").all()}

    reqs = db.query(ServiceRequestModel).filter(
        ServiceRequestModel.customer_id == customer.id
    ).order_by(ServiceRequestModel.created_at.desc()).all()

    catalog_items = db.query(CompanyApplianceCatalogModel).all()

    products_list = []
    has_healed = False
    for a in appliances:
        comp = companies_by_id.get(a.company_id)
        is_w_active = (a.warranty_status or "").lower() == "active"
        app_name = resolve_clean_appliance_name(a, catalog_items=catalog_items, service_requests=reqs)

        # Heal generic appliance names in database
        if is_generic_title(getattr(a, "appliance_name", None), a.brand, a.category) and app_name and not is_generic_title(app_name, a.brand, a.category):
            a.appliance_name = app_name
            has_healed = True

        products_list.append({
            "id": a.id,
            "appliance_id": a.id,
            "appliance_name": app_name,
            "category": a.category,
            "brand": a.brand,
            "company_id": a.company_id,
            "company_name": comp.name if comp else a.brand,
            "model_no": a.model_no,
            "serial_no": a.serial_no or "Not registered",
            "registered_on": a.registered_on,
            "purchase_date": a.purchase_date or a.warranty_start_date or a.registered_on,
            "invoice_url": a.invoice_url,
            "warranty_status": a.warranty_status or "Active",
            "warranty_start_date": a.warranty_start_date or a.registered_on,
            "warranty_end_date": a.warranty_end_date or "Standard 1-Year",
            "is_under_warranty": is_w_active,
            "amc_active": bool(a.amc_active),
            "amc_plan_name": a.amc_plan_name or "None",
            "amc_end_date": a.amc_end_date or "—"
        })

    if has_healed:
        try:
            db.commit()
        except Exception:
            db.rollback()

    techs_by_id = {t.id: t for t in db.query(TechnicianModel).all()}
    branches_by_id = {b.id: b for b in db.query(CompanyBranchModel).all()}

    ongoing = []
    completed = []
    for r in reqs:
        t = techs_by_id.get(r.technician_id)
        b = branches_by_id.get(r.branch_id)
        comp = companies_by_id.get(r.company_id)
        jc = db.query(JobCardModel).filter(JobCardModel.request_id == r.id).first()
        item = {
            "id": r.id,
            "appliance_id": r.appliance_id,
            "appliance_name": r.appliance_name,
            "brand": r.brand,
            "model_no": r.model_no,
            "issue": r.issue,
            "status": r.status,
            "status_badge": r.status_badge,
            "priority": r.priority,
            "appointment_date": r.appointment_date,
            "appointment_slot": r.appointment_slot,
            "technician_id": r.technician_id,
            "technician_name": t.name if t else "Unassigned",
            "branch_id": r.branch_id,
            "branch_name": b.branch_name if b else "Authorized Hub",
            "company_id": r.company_id,
            "company_name": comp.name if comp else r.brand,
            "created_at": r.created_at,
            "payment_status": r.payment_status or "Pending",
            "total_amount": jc.total_amount if jc else 0.0
        }
        if r.status == "Completed" or r.status_badge == "Completed":
            completed.append(item)
        else:
            ongoing.append(item)

    return {
        "customer": {
            "id": customer.id,
            "name": customer.name,
            "email": customer.email,
            "phone": customer.phone,
            "address": customer.address or "Address not provided",
            "avatar": customer.name[:2].upper(),
            "is_active": customer.is_active,
            "appliances_count": len(products_list),
            "total_requests": len(reqs),
            "ongoing_requests": len(ongoing),
            "completed_requests": len(completed)
        },
        "stats": {
            "total_products": len(products_list),
            "active_warranties": sum(1 for p in products_list if p.get("is_under_warranty")),
            "ongoing_services": len(ongoing),
            "completed_services": len(completed)
        },
        "products": products_list,
        "appliances": products_list,
        "ongoing_services": ongoing,
        "completed_services": completed,
        "requests": ongoing + completed
    }


@router.get("/technicians/{technician_id}")
def get_admin_technician_details(technician_id: str, request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    t = db.query(TechnicianModel).filter(TechnicianModel.id == technician_id).first()
    if not t or technician_id in ("tech_1", "tech_2") or (t.name in ("Rahul Sharma", "Suresh Kumar")):
        raise HTTPException(status_code=404, detail="Technician not found")

    link = db.query(BranchTechnicianModel).filter(BranchTechnicianModel.technician_id == t.id).first()
    branch = db.query(CompanyBranchModel).filter(CompanyBranchModel.id == link.branch_id).first() if link else None
    company = db.query(UserModel).filter(UserModel.id == branch.company_id).first() if branch else None
    t_user = db.query(UserModel).filter(or_(UserModel.id == t.id, UserModel.phone == t.phone)).first()

    reqs = db.query(ServiceRequestModel).filter(
        ServiceRequestModel.technician_id == t.id
    ).order_by(ServiceRequestModel.created_at.desc()).all()

    assigned_services = []
    for r in reqs:
        assigned_services.append({
            "id": r.id,
            "customer_name": r.customer_name,
            "customer_phone": r.customer_phone,
            "appliance_name": r.appliance_name,
            "brand": r.brand,
            "issue": r.issue,
            "status": r.status,
            "status_badge": r.status_badge,
            "appointment_date": r.appointment_date,
            "appointment_slot": r.appointment_slot
        })

    onb = db.query(TechnicianOnboardingModel).filter_by(technician_id=t.id).first() if t else None
    pw_set = bool(onb and onb.password_set_at)
    pw_set_at = f"{onb.password_set_at.isoformat()}Z" if (onb and onb.password_set_at) else None
    raw_created = (link.created_at if link else None) or (getattr(t_user, "created_at", None) if t_user else None)
    created_at_val = f"{raw_created.isoformat()}Z" if (raw_created and not raw_created.isoformat().endswith("Z")) else (raw_created.isoformat() if raw_created else None)

    return {
        "technician": {
            "id": t.id,
            "name": t.name,
            "title": t.title or "Field Service Engineer",
            "phone": t.phone,
            "email": t_user.email if t_user else f"{t.name.lower().replace(' ', '.')}@servsure.com",
            "rating": round(t.rating or 5.0, 1),
            "total_jobs": len(reqs) if len(reqs) > 0 else (t.total_jobs or 0),
            "branch_id": branch.id if branch else None,
            "branch_name": branch.branch_name if branch else (t.company_branch or "Main Service Center"),
            "branch_address": branch.address if branch else "—",
            "manager_name": branch.manager_name if branch else "—",
            "company_id": company.id if company else None,
            "company_name": company.name if company else "ServSure Certified Partner",
            "address": (link.address if link else None) or (branch.address if branch else "Field Service Territory"),
            "pincode": (link.pincode if link else None) or (branch.pincode if branch else ""),
            "is_active": getattr(t_user, "is_active", False) if t_user else False,
            "is_verified": t.is_verified,
            "password_set": pw_set,
            "password_set_at": pw_set_at,
            "created_at": created_at_val,
            "avatar": t.avatar or t.name[:2].upper()
        },
        "services": assigned_services
    }


@router.get("/branches/{branch_id}")
def get_admin_branch_details(branch_id: str, request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    from app.routes.company import get_company_branch_details
    return get_company_branch_details(branch_id, request, db)


@router.post("/companies", status_code=201)
def create_company(payload: CompanyCreate, request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    email = payload.email.strip().lower()
    if db.query(UserModel).filter(UserModel.email.ilike(email)).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    # Fail before inserting the account when email delivery cannot be attempted.
    if not os.getenv("BREVO_API_KEY") or not os.getenv("BREVO_SENDER_EMAIL"):
        raise HTTPException(status_code=503, detail="Brevo is not configured. Set BREVO_API_KEY and BREVO_SENDER_EMAIL on the backend.")
    company = UserModel(
        id=f"company_{uuid4().hex[:12]}", name=payload.name.strip(), email=email,
        phone=payload.phone.strip(), role="company", address=(payload.address or "").strip() or None,
        password_hash=None, is_active=False, created_at=datetime.utcnow(),
    )
    db.add(company)
    db.flush()
    onboarding = CompanyOnboardingModel(company_id=company.id)
    db.add(onboarding)
    try:
        issue_invite(company, onboarding)
        db.commit()
        db.refresh(company)
        return company_payload(company, onboarding)
    except Exception:
        db.rollback()
        raise


@router.post("/companies/send-credentials")
def send_company_credentials(payload: CompanyCredentialsEmail, request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    company = db.query(UserModel).filter(UserModel.id == payload.company_id, UserModel.role == "company").first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    onboarding = db.query(CompanyOnboardingModel).filter_by(company_id=company.id).first()
    if not onboarding:
        onboarding = CompanyOnboardingModel(company_id=company.id)
        db.add(onboarding)
    elif onboarding.password_set_at:
        raise HTTPException(status_code=409, detail="This company has already set its password")
    issue_invite(company, onboarding)
    db.commit()
    return {"status": "sent", "email": company.email, "message": "Password setup link sent"}


@router.post("/branches", status_code=201)
def create_admin_branch(payload: CompanyBranchCreate, request: Request, db: Session = Depends(get_db)):
    admin = require_admin(request, db)
    email = payload.email.strip().lower()
    existing_branch = db.query(CompanyBranchModel).filter(CompanyBranchModel.email.ilike(email)).first()
    if existing_branch:
        # Existing branch already registered with a company or network: update in place without creating duplicate accounts
        if payload.branch_name and payload.branch_name.strip():
            existing_branch.branch_name = payload.branch_name.strip()
        if payload.manager_name and payload.manager_name.strip():
            existing_branch.manager_name = payload.manager_name.strip()
        if payload.mobile and payload.mobile.strip():
            existing_branch.mobile = payload.mobile.strip()
        if payload.address and payload.address.strip():
            existing_branch.address = payload.address.strip()
        if payload.pincode and payload.pincode.strip():
            existing_branch.pincode = payload.pincode.strip()

        dealer_companies_val = (payload.dealer_companies or "").strip() or None
        if dealer_companies_val:
            old_cos = [c.strip() for c in (existing_branch.dealer_companies or "").split(",") if c.strip()]
            new_cos = [c.strip() for c in dealer_companies_val.split(",") if c.strip()]
            combined = list(dict.fromkeys(old_cos + new_cos))
            existing_branch.dealer_companies = ", ".join(combined) if combined else None
            existing_branch.is_dual_registered = True
            existing_branch.is_dealer_franchise = True
            existing_branch.registration_mode = "dual"

        if not existing_branch.branch_code:
            clean_id = (existing_branch.id or "").replace("branch_", "").replace("-", "")
            existing_branch.branch_code = f"BR-{clean_id[:6].upper()}"

        db.commit()
        db.refresh(existing_branch)

        branch_user = db.query(UserModel).filter((UserModel.id == existing_branch.id) | (UserModel.email.ilike(existing_branch.email))).first()
        onb = db.query(BranchOnboardingModel).filter(BranchOnboardingModel.branch_id == existing_branch.id).first()
        is_pw_set = bool(onb and onb.password_set_at)

        parent_company = db.query(UserModel).filter(UserModel.id == existing_branch.company_id).first() if existing_branch.company_id else None
        comp_name = parent_company.name if parent_company else ("Multi-Brand Local Dealer Hub" if getattr(existing_branch, "is_dealer_franchise", False) or getattr(existing_branch, "dealer_companies", None) else "ServSure Network")

        branch_ids = [existing_branch.id]
        if branch_user and branch_user.id != existing_branch.id:
            branch_ids.append(branch_user.id)
        tech_links = db.query(BranchTechnicianModel).filter(BranchTechnicianModel.branch_id.in_(branch_ids)).all()
        linked_tech_ids = [tl.technician_id for tl in tech_links]
        named_tech_ids = [
            t.id for t in db.query(TechnicianModel).filter(
                TechnicianModel.company_branch.ilike(existing_branch.branch_name.strip())
            ).all()
        ] if existing_branch.branch_name else []
        assigned_tech_ids = list(set(linked_tech_ids + named_tech_ids))
        tech_count = len(assigned_tech_ids)

        job_filters = [ServiceRequestModel.branch_id.in_(branch_ids)]
        if assigned_tech_ids:
            job_filters.append(ServiceRequestModel.technician_id.in_(assigned_tech_ids))
        if existing_branch.pincode and len(existing_branch.pincode.strip()) == 6:
            job_filters.append(ServiceRequestModel.pincode == existing_branch.pincode.strip())
        jobs_query = db.query(ServiceRequestModel).filter(or_(*job_filters))
        jobs_count = jobs_query.count()
        ongoing_jobs = jobs_query.filter(ServiceRequestModel.status_badge != "Completed").count()

        return {
            "id": existing_branch.id,
            "branch_code": existing_branch.branch_code,
            "name": existing_branch.branch_name,
            "branch_name": existing_branch.branch_name,
            "manager_name": existing_branch.manager_name,
            "company_id": existing_branch.company_id,
            "company_name": comp_name,
            "parent_company_name": parent_company.name if parent_company else None,
            "email": existing_branch.email,
            "phone": existing_branch.mobile,
            "mobile": existing_branch.mobile,
            "address": existing_branch.address,
            "pincode": existing_branch.pincode,
            "dealer_companies": existing_branch.dealer_companies,
            "is_dealer_franchise": existing_branch.is_dealer_franchise,
            "is_dual_registered": existing_branch.is_dual_registered,
            "registration_mode": existing_branch.registration_mode,
            "is_active": branch_user.is_active if branch_user else False,
            "password_set": is_pw_set,
            "password_set_at": onb.password_set_at.isoformat() + "Z" if (onb and onb.password_set_at) else None,
            "created_at": existing_branch.created_at.isoformat() + "Z" if existing_branch.created_at else None,
            "total_techs": tech_count,
            "total_jobs": jobs_count,
            "ongoing_jobs": ongoing_jobs,
            "role": "branch",
            "avatar": existing_branch.branch_name[:2].upper()
        }

    if db.query(UserModel).filter(UserModel.email.ilike(email)).first():
        raise HTTPException(status_code=409, detail="A ServSure account with this email already exists")
    if not os.getenv("BREVO_API_KEY") or not os.getenv("BREVO_SENDER_EMAIL"):
        raise HTTPException(status_code=503, detail="Brevo is not configured. Set BREVO_API_KEY and BREVO_SENDER_EMAIL on the backend.")

    branch_id = f"branch_{uuid4().hex[:12]}"
    branch_code = f"BR-{uuid4().hex[:6].upper()}"
    company_id = payload.company_id if payload.company_id else admin.id
    dealer_companies_val = (payload.dealer_companies or "").strip() or None
    is_dealer = bool(payload.is_dealer_franchise or dealer_companies_val or not payload.company_id)
    reg_mode = (payload.registration_mode or "").strip().lower()
    is_dual = bool(payload.is_dual_registered or reg_mode == "dual" or (payload.company_id and (is_dealer or dealer_companies_val)))
    if is_dual:
        reg_mode = "dual"
    elif not reg_mode:
        reg_mode = "individual" if is_dealer else "company"

    branch = CompanyBranchModel(
        id=branch_id,
        branch_code=branch_code,
        company_id=company_id,
        branch_name=payload.branch_name.strip(),
        manager_name=payload.manager_name.strip(),
        email=email,
        mobile=payload.mobile.strip(),
        address=payload.address.strip(),
        pincode=payload.pincode.strip(),
        dealer_companies=dealer_companies_val,
        is_dealer_franchise=is_dealer,
        is_dual_registered=is_dual,
        registration_mode=reg_mode,
        created_at=datetime.utcnow(),
    )
    branch_user = UserModel(
        id=branch_id,
        name=branch.manager_name,
        email=email,
        phone=branch.mobile,
        role="branch",
        address=f"{branch.address}, {branch.pincode}",
        password_hash=None,
        is_active=False,
        created_at=datetime.utcnow(),
    )
    onboarding = BranchOnboardingModel(branch_id=branch_id)
    db.add(branch_user)
    try:
        db.flush()
        db.add_all([branch, onboarding])
        db.flush()

        token = secrets.token_urlsafe(32)
        onboarding.invite_token_hash = digest(token)
        onboarding.invite_expires_at = datetime.utcnow() + timedelta(hours=48)
        frontend_url = os.getenv("FRONTEND_BASE_URL", "https://servsure.vercel.app").rstrip("/")
        setup_url = f"{frontend_url}/franchise-setup.html?token={token}"

        parent_company = db.query(UserModel).filter(UserModel.id == company_id).first()
        inviter_name = parent_company.name if (parent_company and parent_company.role == "company") else "ServSure Platform Administrator"

        brands_html = f"<li><strong>Represented Brand Partnerships:</strong> {html.escape(dealer_companies_val)}</li>" if dealer_companies_val else ""
        brands_txt = f"\nRepresented Brands: {dealer_companies_val}" if dealer_companies_val else ""

        send_brevo_email(
            branch.email,
            branch.manager_name,
            "Your ServSure franchise portal is ready",
            f"Hello {branch.manager_name},\n\nYour franchise branch / local dealer hub has been registered on ServSure by {inviter_name}.\n\nBranch: {branch.branch_name}\nAddress: {branch.address}, {branch.pincode}{brands_txt}\n\nSet up your password and verify your email using this link (valid for 48 hours):\n{setup_url}\n\nYour registered login email is {branch.email}.",
            f"<p>Hello {html.escape(branch.manager_name)},</p><p>Your franchise branch / local dealer hub has been registered on ServSure by <strong>{html.escape(inviter_name)}</strong>.</p><ul><li><strong>Branch:</strong> {html.escape(branch.branch_name)}</li><li><strong>Address:</strong> {html.escape(branch.address)}, {html.escape(branch.pincode)}</li>{brands_html}</ul><p>Create your password and verify your email using the link below. The link expires in 48 hours.</p><p><a href=\"{html.escape(setup_url, quote=True)}\">Set up your franchise portal password</a></p><p>Registered login email: <strong>{html.escape(branch.email)}</strong></p>",
        )
        db.commit()
        db.refresh(branch)

        return {
            "id": branch.id,
            "branch_code": branch.branch_code,
            "name": branch.branch_name,
            "branch_name": branch.branch_name,
            "manager_name": branch.manager_name,
            "company_id": branch.company_id,
            "company_name": inviter_name if inviter_name != "ServSure Platform Administrator" else "Multi-Brand Local Dealer Hub",
            "email": branch.email,
            "phone": branch.mobile,
            "mobile": branch.mobile,
            "address": branch.address,
            "pincode": branch.pincode,
            "dealer_companies": branch.dealer_companies,
            "is_dealer_franchise": branch.is_dealer_franchise,
            "is_dual_registered": branch.is_dual_registered,
            "registration_mode": branch.registration_mode,
            "is_active": False,
            "password_set": False,
            "password_set_at": None,
            "created_at": branch.created_at.isoformat() + "Z",
            "total_techs": 0,
            "total_jobs": 0,
            "ongoing_jobs": 0,
            "role": "branch",
            "avatar": branch.branch_name[:2].upper()
        }
    except Exception:
        db.rollback()
        raise


@router.get("/preadded-branches")
def list_preadded_company_branches(request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    companies_by_id = {u.id: u for u in db.query(UserModel).filter(UserModel.role == "company").all()}
    all_branches = db.query(CompanyBranchModel).order_by(CompanyBranchModel.branch_name).all()

    result = []
    for b in all_branches:
        # Preadded branches must belong to an active OEM company
        if b.company_id not in companies_by_id:
            continue

        company = companies_by_id.get(b.company_id)
        c_name = company.name if company else "Registered Company"
        b_code = getattr(b, "branch_code", None) or f"BR-{b.id.replace('branch_', '')[:6].upper()}"
        result.append({
            "id": b.id,
            "branch_code": b_code,
            "branch_name": b.branch_name,
            "company_id": b.company_id,
            "company_name": c_name,
            "parent_company_name": c_name,
            "manager_name": b.manager_name,
            "email": b.email,
            "mobile": b.mobile,
            "address": b.address,
            "pincode": b.pincode,
            "dealer_companies": getattr(b, "dealer_companies", None) or "",
            "is_dealer_franchise": bool(getattr(b, "is_dealer_franchise", False)),
            "is_dual_registered": bool(getattr(b, "is_dual_registered", False)),
            "registration_mode": getattr(b, "registration_mode", None) or "standard",
            "created_at": b.created_at.isoformat() if b.created_at else None,
        })
    return result


@router.post("/branches/configure-preadded")
def configure_preadded_branch(payload: PreaddedBranchConfigure, request: Request, db: Session = Depends(get_db)):
    admin = require_admin(request, db)
    branch = db.query(CompanyBranchModel).filter(CompanyBranchModel.id == payload.branch_id).first()
    if not branch:
        raise HTTPException(status_code=404, detail="Branch not found")

    company = db.query(UserModel).filter(UserModel.id == branch.company_id).first() if branch.company_id else None
    company_name = company.name if company else ("Multi-Brand Local Dealer Hub" if getattr(branch, "is_dealer_franchise", False) or getattr(branch, "dealer_companies", None) else "ServSure Network")

    if payload.manager_name and payload.manager_name.strip():
        branch.manager_name = payload.manager_name.strip()
    if payload.mobile and payload.mobile.strip():
        branch.mobile = payload.mobile.strip()
    if payload.address and payload.address.strip():
        branch.address = payload.address.strip()
    if payload.pincode and payload.pincode.strip():
        branch.pincode = payload.pincode.strip()

    if payload.partnership_mode == "current_only":
        branch.dealer_companies = None
        branch.is_dual_registered = False
        branch.is_dealer_franchise = False
        branch.registration_mode = "standard"
    elif payload.partnership_mode == "add_more":
        dealer_cos = (payload.dealer_companies or "").strip()
        branch.dealer_companies = dealer_cos if dealer_cos else None
        branch.is_dual_registered = True
        branch.is_dealer_franchise = True
        branch.registration_mode = "dual"

    if not branch.branch_code:
        clean_id = (branch.id or "").replace("branch_", "").replace("-", "")
        branch.branch_code = f"BR-{clean_id[:6].upper()}"

    db.commit()
    db.refresh(branch)

    branch_user = db.query(UserModel).filter((UserModel.id == branch.id) | (UserModel.email.ilike(branch.email))).first()
    onb = db.query(BranchOnboardingModel).filter(BranchOnboardingModel.branch_id == branch.id).first()
    is_pw_set = bool(onb and onb.password_set_at)

    branch_ids = [branch.id]
    if branch_user and branch_user.id != branch.id:
        branch_ids.append(branch_user.id)
    tech_links = db.query(BranchTechnicianModel).filter(BranchTechnicianModel.branch_id.in_(branch_ids)).all()
    linked_tech_ids = [tl.technician_id for tl in tech_links]
    named_tech_ids = [
        t.id for t in db.query(TechnicianModel).filter(
            TechnicianModel.company_branch.ilike(branch.branch_name.strip())
        ).all()
    ] if branch.branch_name else []
    assigned_tech_ids = list(set(linked_tech_ids + named_tech_ids))
    tech_count = len(assigned_tech_ids)

    job_filters = [ServiceRequestModel.branch_id.in_(branch_ids)]
    if assigned_tech_ids:
        job_filters.append(ServiceRequestModel.technician_id.in_(assigned_tech_ids))
    if branch.pincode and len(branch.pincode.strip()) == 6:
        job_filters.append(ServiceRequestModel.pincode == branch.pincode.strip())
    jobs_query = db.query(ServiceRequestModel).filter(or_(*job_filters))
    jobs_count = jobs_query.count()
    ongoing_jobs = jobs_query.filter(ServiceRequestModel.status_badge != "Completed").count()

    return {
        "success": True,
        "message": f"{branch.branch_name} ({branch.branch_code}) configured successfully.",
        "branch": {
            "id": branch.id,
            "branch_code": branch.branch_code,
            "name": branch.branch_name,
            "branch_name": branch.branch_name,
            "manager_name": branch.manager_name,
            "company_id": branch.company_id,
            "company_name": company_name,
            "parent_company_name": company.name if company else None,
            "email": branch.email,
            "phone": branch.mobile,
            "mobile": branch.mobile,
            "address": branch.address,
            "pincode": branch.pincode,
            "dealer_companies": branch.dealer_companies,
            "is_dealer_franchise": branch.is_dealer_franchise,
            "is_dual_registered": branch.is_dual_registered,
            "registration_mode": branch.registration_mode,
            "is_active": branch_user.is_active if branch_user else False,
            "password_set": is_pw_set,
            "password_set_at": onb.password_set_at.isoformat() + "Z" if (onb and onb.password_set_at) else None,
            "created_at": branch.created_at.isoformat() + "Z" if branch.created_at else None,
            "total_techs": tech_count,
            "total_jobs": jobs_count,
            "ongoing_jobs": ongoing_jobs,
            "role": "branch",
            "avatar": branch.branch_name[:2].upper()
        }
    }


@router.put("/branches/{branch_id}/access")
def toggle_admin_branch_access(branch_id: str, payload: AccessTogglePayload, request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    branch = db.query(CompanyBranchModel).filter(CompanyBranchModel.id == branch_id).first()
    if not branch:
        raise HTTPException(status_code=404, detail="Franchise branch not found")

    branch_user = db.query(UserModel).filter(
        (UserModel.id == branch.id) | (UserModel.email == branch.email)
    ).first()
    if branch_user:
        branch_user.is_active = payload.is_active

    if not payload.is_active:
        if branch_user:
            revoke_all_user_sessions(branch_user.id, db)
        revoke_all_user_sessions(branch.id, db)
        tech_links = db.query(BranchTechnicianModel).filter(BranchTechnicianModel.branch_id == branch.id).all()
        for bt in tech_links:
            revoke_all_user_sessions(bt.technician_id, db)

    db.commit()
    if branch_user:
        db.refresh(branch_user)
    return {
        "status": "success",
        "message": f"Franchise branch access {'enabled' if payload.is_active else 'disabled'} successfully",
        "is_active": payload.is_active
    }


def get_setup_context(token: str, email: str, db: Session):
    onboarding = db.query(CompanyOnboardingModel).filter_by(invite_token_hash=digest(token)).first()
    if not onboarding or not onboarding.invite_expires_at or onboarding.invite_expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="This password setup link is invalid or expired. Ask ServSure to send a new one.")
    company = db.query(UserModel).filter_by(id=onboarding.company_id, role="company").first()
    if not company or not hmac.compare_digest(company.email.lower(), email.strip().lower()):
        raise HTTPException(status_code=400, detail="Enter the email address registered with ServSure")
    if onboarding.password_set_at:
        raise HTTPException(status_code=400, detail="This company account is already set up. Please sign in.")
    return company, onboarding


@onboarding_router.post("/company/password")
def begin_company_password_setup(payload: CompanyPasswordSetup, db: Session = Depends(get_db)):
    company, onboarding = get_setup_context(payload.token, payload.email, db)
    otp = f"{secrets.randbelow(1_000_000):06d}"
    onboarding.pending_password_hash = make_password_hash(payload.password)
    onboarding.otp_hash = digest(f"{onboarding.company_id}:{otp}")
    onboarding.otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
    try:
        send_brevo_email(
            company.email, company.name, "Your ServSure verification code",
            f"Your ServSure verification code is {otp}. It expires in 10 minutes. If you did not request this, ignore this email.",
            f"<p>Your ServSure verification code is:</p><p style=\"font-size:28px;font-weight:700;letter-spacing:6px\">{otp}</p><p>This code expires in 10 minutes.</p>",
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"status": "otp_sent", "email": company.email, "message": "Verification code sent to your registered email"}


@onboarding_router.post("/company/verify-otp")
def verify_company_setup_otp(payload: CompanyOtpVerify, db: Session = Depends(get_db)):
    company, onboarding = get_setup_context(payload.token, payload.email, db)
    if not onboarding.pending_password_hash or not onboarding.otp_hash or not onboarding.otp_expires_at:
        raise HTTPException(status_code=400, detail="Request a verification code first")
    if onboarding.otp_expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Verification code expired. Go back and request a new code.")
    submitted = digest(f"{company.id}:{payload.otp}")
    if not hmac.compare_digest(onboarding.otp_hash, submitted):
        raise HTTPException(status_code=400, detail="The verification code is incorrect")
    company.password_hash = onboarding.pending_password_hash
    company.is_active = True
    onboarding.password_set_at = datetime.utcnow()
    onboarding.pending_password_hash = None
    onboarding.otp_hash = None
    onboarding.otp_expires_at = None
    onboarding.invite_token_hash = None
    onboarding.invite_expires_at = None
    db.commit()
    frontend_url = os.getenv("FRONTEND_BASE_URL", "https://servsure.vercel.app").rstrip("/")
    portal_url = f"{frontend_url}/company-login.html"
    confirmation_email_sent = False
    safe_name = html.escape(company.name)
    safe_url = html.escape(portal_url, quote=True)
    try:
        send_brevo_email(
            company.email, company.name, "Your ServSure company password is set",
            f"Hello {company.name},\n\nYour ServSure company admin password has been set successfully. You can now access your company portal using your registered email and password:\n{portal_url}\n\nIf you did not make this change, please contact ServSure support.",
            f"<p>Hello {safe_name},</p><p>Your ServSure company admin password has been set successfully. You can now access your company portal using your registered email and password.</p><p><a href=\"{safe_url}\">Open the ServSure company portal</a></p><p>If you did not make this change, please contact ServSure support.</p>",
        )
        confirmation_email_sent = True
    except Exception:
        # Password setup is already committed; report email delivery separately
        # so the company is not incorrectly prompted to repeat OTP verification.
        pass
    return {
        "status": "password_set", "email": company.email,
        "password_set_at": onboarding.password_set_at.isoformat(),
        "confirmation_email_sent": confirmation_email_sent,
        "portal_login_url": portal_url,
    }
