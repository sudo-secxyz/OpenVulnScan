#utils/settings.py
from fastapi import APIRouter, Request, Depends, Form, Body, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from database.db_manager import get_db
from models.users import User
from models.package import Package
from models.cve import CVE
from models.agent_report import AgentReport
from utils.agent_router import AgentReport
from passlib.context import CryptContext
from itsdangerous import URLSafeSerializer, BadSignature
from starlette.status import HTTP_303_SEE_OTHER
from auth.dependencies import require_authentication , get_current_user, cookie_signer
import httpx
from utils import config  
from utils.get_system_time import get_system_timezone
import logging


logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="templates")
serializer = cookie_signer
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")



@router.get("/settings", response_class=HTMLResponse, dependencies=[Depends(require_authentication)], tags=["Configuration"])
def settings_page(request: Request, user: User = Depends(get_current_user)):
    """ Display settings page """
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "cve_api_url": config.CVE_API_URL,  # Accessing config here
        "current_user": user
    })

@router.post("/settings/change-password", tags=["Configuration"])
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    try:
        logger.info(f"User {user.email} is attempting to change password.")

        if new_password != confirm_password:
            logger.warning("Passwords do not match.")
            return templates.TemplateResponse("settings.html", {"request": request, "error": "Passwords do not match.", "current_user": user})

        if not pwd_context.verify(current_password, user.hashed_password):
            logger.warning("Incorrect current password.")
            return templates.TemplateResponse("settings.html", {"request": request, "error": "Incorrect current password.", "current_user": user})

        db_user = db.query(User).filter(User.id == user.id).first()
        db_user.hashed_password = pwd_context.hash(new_password)
        db.commit()

        # Reload user from DB
        logger.info("Password successfully updated.")

        return templates.TemplateResponse("settings.html", {"request": request, "success": "Password updated successfully.", "current_user": db_user})
    
    except Exception as e:
        logger.error(f"Exception in password change: {e}")
        return templates.TemplateResponse("settings.html", {"request": request, "error": "Something went wrong.", "current_user": user})




@router.post("/settings/update", tags=["Configuration"])
def update_settings(
    request: Request,
    cve_api_url: str = Form(...),
    user: User = Depends(get_current_user)
):
    # Update .env file
    env_path = ".env"
    updated_lines = []

    # Read current .env and update or add the CVE_API_URL line
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            lines = f.readlines()

        for line in lines:
            if line.startswith("CVE_API_URL="):
                updated_lines.append(f"CVE_API_URL={cve_api_url}\n")
            else:
                updated_lines.append(line)

        if not any(line.startswith("CVE_API_URL=") for line in lines):
            updated_lines.append(f"CVE_API_URL={cve_api_url}\n")
    else:
        updated_lines = [f"CVE_API_URL={cve_api_url}\n"]

    with open(env_path, "w") as f:
        f.writelines(updated_lines)

    # Update runtime config too
    config.CVE_API_URL = cve_api_url

    return RedirectResponse(url="/settings", status_code=HTTP_303_SEE_OTHER)

@router.post("/cve/check", response_class=JSONResponse, dependencies=[Depends(require_authentication)], tags=["agent"])
async def check_package_cves(
    payload: dict = Body(...), user: User = Depends(get_current_user)
):
    try:
        query = {
            "package": {
                "name": payload["name"],
                "ecosystem": payload.get("ecosystem", "Debian")
            },
            "version": payload["version"]
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(config.CVE_API_URL, json=query)
            response.raise_for_status()
            data = response.json()
            return {
                "status": "success",
                "query": query,
                "vulnerabilities": data.get("vulns", [])
            }

    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/dashboard", response_class=HTMLResponse, tags=['agent'])
def dashboard(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    report_count = db.scalar(select(func.count()).select_from(AgentReport))
    package_count = db.scalar(select(func.count()).select_from(Package))
    cve_count = db.scalar(select(func.count()).select_from(CVE))

    top_packages_query = (
        select(Package.name, func.count(CVE.id).label("cve_count"))
        .join(CVE, CVE.package_id == Package.id)
        .group_by(Package.name)
        .order_by(func.count(CVE.id).desc())
        .limit(5)
    )
    top_packages = db.execute(top_packages_query).all()

    latest_reports_query = (
        select(AgentReport.hostname, AgentReport.id.label("latest_report_id"), AgentReport.reported_at)
        .distinct(AgentReport.hostname)
        .order_by(AgentReport.hostname, AgentReport.reported_at.desc())
    )
    agents = db.execute(latest_reports_query).all()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "report_count": report_count,
        "package_count": package_count,
        "cve_count": cve_count,
        "top_packages": top_packages,
        "agents": agents,
        "current_user": user
    })
@router.get("/settings/timezone")
def get_timezone():
    return {"timezone": get_system_timezone()}