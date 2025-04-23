from fastapi import APIRouter, Request, Depends, status, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime
from auth.dependencies import require_authentication
from database.db_manager import get_db
from models.agent_report import AgentReport, Package, CVE
from utils import cve_checker
import uuid

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
    db.commit()
    db.refresh(report)

    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")

        if name and version:
            package = Package(name=name, version=version, report_id=report.id)
            db.add(package)

            # 🔍 Optional: Check CVE data here via your integrated CVE API
            matched_cves = cve_checker.check_cves_for_package(name, version)
            for cve in matched_cves:
                

                CveId = cve.get("id", "UNKNOWN-CVE")

                # Use `details` as the summary if it's a string
                CveSummary = cve.get("details") or "No summary available"

                # Safely parse the severity vector string from the first entry (if any)
                severity_list = cve.get("severity", [])
                if isinstance(severity_list, list) and severity_list:
                    CveSeverity = severity_list[0].get("score", "Unknown")
                else:
                    CveSeverity = "Unknown"

                db.add(CVE(
                    cve_id=CveId,
                    summary=CveSummary,
                    severity=CveSeverity,
                    package=package
                ))
                
                db.add(CVE(cve_id=CveId, summary=CveSummary, severity=CveSeverity, package=package))
    db.commit()

    return {"detail": "Agent report submitted successfully", "report_id": report.id}

@router.get("/agent/report/{report_id}", dependencies=[Depends(require_authentication)], tags=["agent"])
def get_agent_report(report_id: str, db: Session = Depends(get_db)):
    # Fetch the agent report by report_id
    report = db.query(AgentReport).filter(AgentReport.id == report_id).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Agent report not found")
    
    # Fetch the associated packages for this report
    packages = db.query(Package).filter(Package.report_id == report.id).all()
    
    # Optionally, fetch CVEs for each package (if the data is populated)
    package_data = []
    for package in packages:
        cves = db.query(CVE).filter(CVE.package_id == package.id).all()
        package_data.append({
            "package_name": package.name,
            "version": package.version,
            "cves": [{"cve_id": cve.cve_id, "summary": cve.summary, "severity": cve.severity} for cve in cves]
        })
    
    # Return the report with package and CVE data
    return {
        "report_id": report.id,
        "hostname": report.hostname,
        "os": report.os_info,  # Assuming you want the OS info in the response
        "reported_at": report.reported_at,
        "packages": package_data
    }

@router.get("/agent/reports", dependencies=[Depends(require_authentication)], tags=["agent"])
def list_agent_reports(db: Session = Depends(get_db)):
    reports = db.query(AgentReport).all()

    all_reports = []
    for report in reports:
        packages = db.query(Package).filter(Package.report_id == report.id).all()
        all_reports.append({
            "report_id": report.id,
            "hostname": report.hostname,
            "reported_at": report.reported_at,
            "package_count": len(packages),
        })

    return all_reports