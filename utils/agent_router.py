#utils/agent_router.py
from fastapi import APIRouter, Request, Depends, status, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from datetime import datetime
from models.schemas import ScanRequest, ScanTaskResponse
from database.db_manager import get_db
from models.agent_report import AgentReport
from models.package import Package
from models.cve import CVE
from models.users import User
from utils import cve_checker
from utils.syslog import send_syslog_message
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from itsdangerous import URLSafeSerializer
from auth.dependencies import require_authentication, get_current_user, cookie_signer
import json

# Initialize router and session serializer
router = APIRouter()
serializer = cookie_signer
# Submit agent report
@router.post("/agent/report", status_code=201)
async def submit_agent_report(payload: dict, db: Session = Depends(get_db)):
    try:
        # Create agent report
        report = AgentReport(
            hostname=payload["hostname"],
            os_info=payload.get("os_info", "Unknown"),
            reported_at=datetime.utcnow()
        )
        db.add(report)
        db.flush()

        # Process enriched packages
        for pkg_data in payload["packages"]:
            package = Package(
                name=pkg_data["name"],
                version=pkg_data["version"],
                report_id=report.id
            )
            db.add(package)
            db.flush()

            # Store pre-enriched CVEs
            for cve_data in pkg_data.get("cves", []):
                cve = CVE(
                    cve_id=cve_data["id"],
                    summary=cve_data["summary"],
                    severity=cve_data["severity"],
                    cvss=str(cve_data.get("cvss", "")),
                    remediation=cve_data.get("remediation", ""),
                    package_id=package.id
                )
                db.add(cve)

        db.commit()
        return {"detail": "Agent report submitted successfully", "report_id": report.id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error processing report: {str(e)}")

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

