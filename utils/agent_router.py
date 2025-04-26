#utils/agent_router.py
from fastapi import APIRouter, Request, Depends, status, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from datetime import datetime
from database.db_manager import get_db
from models.agent_report import AgentReport, Package, CVE
from models.users import User
from utils import cve_checker
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from itsdangerous import URLSafeSerializer
from auth.dependencies import require_authentication, get_current_user, cookie_signer

# Initialize router and session serializer
router = APIRouter()
serializer = cookie_signer
# Submit agent report
@router.post("/agent/report", status_code=201,  tags=["agent"])
def submit_agent_report(request: Request, payload: dict, db: Session = Depends(get_db)):
    hostname = payload.get("hostname")
    os_info = payload.get("os")
    packages = payload.get("packages", [])

    if not hostname or not packages:
        return JSONResponse(status_code=400, content={"detail": "Missing hostname or packages"})

    report = AgentReport(hostname=hostname, os_info=os_info, reported_at=datetime.utcnow())
    db.add(report)
    db.flush()  # Assign ID before using in foreign key

    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")

        if not name or not version:
            continue

        package = Package(name=name, version=version, report_id=report.id)
        db.add(package)
        db.flush()  # Assign ID before using in CVE

        matched_cves = cve_checker.check_cve_api(name, version)
        for cve in matched_cves:
            cve_id = cve.get("id", "UNKNOWN-CVE")
            summary = cve.get("details", "No summary available")
            severity_list = cve.get("severity", [])
            severity = severity_list[0].get("score", "Unknown") if severity_list else "Unknown"

            db.add(CVE(
                cve_id=cve_id,
                summary=summary,
                severity=severity,
                package_id=package.id
            ))

    db.commit()
    return {"detail": "Agent report submitted successfully", "report_id": report.id}

# Templates for rendering HTML responses
templates = Jinja2Templates(directory="templates")

# Get agent report by ID (requires authentication)
@router.get("/agent/report/{report_id}", response_class=HTMLResponse, tags=["agent"])
def get_agent_report(request: Request, report_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    report = db.get(AgentReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Agent report not found")

    packages = db.scalars(select(Package).where(Package.report_id == report.id)).all()
    package_data = []

    for package in packages:
        cves = db.scalars(select(CVE).where(CVE.package_id == package.id)).all()
        package_data.append({
            "package_name": package.name,
            "version": package.version,
            "cves": [{"cve_id": cve.cve_id, "summary": cve.summary, "severity": cve.severity} for cve in cves]
        })

    return templates.TemplateResponse("report.html", {
        "request": request,
        "report_id": report.id,
        "hostname": report.hostname,
        "os": report.os_info,
        "reported_at": report.reported_at,
        "packages": package_data,
        "current_user": user
    })

# List all agent reports (requires authentication)
@router.get("/agent/reports", tags=["agent"])
def list_agent_reports(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    reports = db.scalars(select(AgentReport)).all()
    results = []

    for report in reports:
        package_count = db.scalar(select(func.count()).where(Package.report_id == report.id))
        results.append({
            "report_id": report.id,
            "hostname": report.hostname,
            "reported_at": report.reported_at,
            "package_count": package_count
        })

    return results

