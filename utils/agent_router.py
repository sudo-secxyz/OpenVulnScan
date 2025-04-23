from fastapi import APIRouter, Request, Depends, status, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from datetime import datetime
from auth.dependencies import require_authentication
from database.db_manager import get_db
from models.agent_report import AgentReport, Package, CVE
from utils import cve_checker

from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

router = APIRouter()

@router.post("/agent/report", status_code=201, dependencies=[Depends(require_authentication)], tags=["agent"])
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

        matched_cves = cve_checker.check_cves_for_package(name, version)
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


templates = Jinja2Templates(directory="templates")

@router.get("/agent/report/{report_id}", response_class=HTMLResponse, dependencies=[Depends(require_authentication)], tags=["agent"])
def get_agent_report(request: Request, report_id: str, db: Session = Depends(get_db)):
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
        "packages": package_data
    })

@router.get("/agent/reports", dependencies=[Depends(require_authentication)], tags=["agent"])
def list_agent_reports(db: Session = Depends(get_db)):
    reports = db.scalars(select(AgentReport)).all()
    results = []

    for report in reports:
        package_count = db.scalar(
        select(func.count()).where(Package.report_id == report.id)
        )
        results.append({
            "report_id": report.id,
            "hostname": report.hostname,
            "reported_at": report.reported_at,
            "package_count": package_count
        })

    return results
