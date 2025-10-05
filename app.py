# app.py
from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, Request, status, APIRouter, Form
from fastapi.responses import HTMLResponse, FileResponse, Response, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload
import os
import json
import html
import datetime
import models
from sqlalchemy import func


from utils.background import handle_scan
from utils.syslog import send_syslog_message
from database.base import Base
from database.db_manager import engine, SessionLocal, get_db
from database.ops import get_all_scans, get_scan as gs, init_db, get_cve_by_id
from models.finding import Finding
from models.schemas import ScanRequest, ScanResult, ScanTaskResponse
from models.users import User
from models.agent_report import AgentReport
from models.auth import BasicAuthBackend, BasicUser
from models.scan import Scan
from models.asset import Asset
from models.scheduled_scan import ScheduledScan
from models.agent_report import AgentReport
from models.package import Package
from models.cve import CVE
from services.scan_service import start_scan_task
from utils.report_generator import generate_scan_report
from config import TEMPLATES_DIR, STATIC_DIR, initialize_directories, setup_logging
from utils.settings import router as settings_router
from utils.agent_router import router as AgentRouter
from routes.schedule import router as schedule_router
from routes.assets import router as assets_router
from routes.dashboard import router as dashboard_router
from routes.scan import router as scan_router
from passlib.hash import bcrypt
from uuid import uuid4

from itsdangerous import URLSafeSerializer
# Auth Routers
from auth.google import router as google_auth
from routes.siem import router as siem_router
from auth.local import router as local_auth
from auth.dependencies import require_authentication, COOKIE_NAME, get_current_user, cookie_signer

# Middleware
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware, AuthenticationBackend, AuthCredentials
from config import initialize_directories

initialize_directories()
# Logging
logger = setup_logging()

init_db()
# Session management
serializer = cookie_signer

# Initialize middleware in correct order
middleware = [
    Middleware(AuthenticationMiddleware, backend=BasicAuthBackend())
]

# Initialize app
app = FastAPI(title="OpenVulnScan", version="0.1.0", middleware=middleware)

# Setup static and templates
initialize_directories()
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Include public routers
app.include_router(google_auth)
app.include_router(local_auth)
app.include_router(settings_router)
app.include_router(AgentRouter)
app.include_router(schedule_router)
app.include_router(assets_router)

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
def create_scan_record(db: Session, scan_id: str, targets: list[str], status: str, scheduled_for: datetime.datetime | None):
    new_scan = Scan(
        id=scan_id,
        targets=targets,  # Keep as list for JSON column
        status=status,
        started_at=datetime.datetime.utcnow(),
        scheduled_for=scheduled_for
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    return new_scan


# Startup: create admin user
@app.get("/favicon.ico")
async def favicon():
    return RedirectResponse(url="/static/favicon.ico")
@app.on_event("startup")
def create_default_admin():
    Base.metadata.create_all(bind=engine)
    from sqlalchemy import inspect
    inspector = inspect(engine)
    print("Existing tables:", inspector.get_table_names())
    
    db: Session = SessionLocal()
    admin_email = "admin@openvulnscan.local"
    if not db.query(User).filter_by(email=admin_email).first():
        admin = User(
            email=admin_email,
            hashed_password=bcrypt.hash("admin123"),
            is_admin=True,
            role="admin"
        )
        db.add(admin)
        db.commit()
        print(f"Default admin user created: {admin_email}")
    else:
        print("Admin user already exists.")
    db.close()

# Protected router
protected_router = APIRouter()

@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db), user: BasicUser = Depends(get_current_user)):
    # Summary data
    total_scans = db.query(func.count(Scan.id)).scalar()
    completed_scans = db.query(func.count(Scan.id)).filter(Scan.status == "completed").scalar()
    active_scans = db.query(func.count(Scan.id)).filter(Scan.status == "running").scalar()
    # Recent scans
    recent_scans = db.query(Scan).order_by(Scan.started_at.desc()).limit(5).all()

    # Critical vulnerabilities (example: filter by severity)
    critical_vulnerabilities = db.query(func.count()).filter(Scan.status == "completed").scalar()

    return templates.TemplateResponse("index.html", {
        "request": request,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "active_scans": active_scans,
        "recent_scans": recent_scans,
        "critical_vulnerabilities": critical_vulnerabilities,
        "current_user": user
    })
from utils.tasks import run_scan, schedule_scan  # You’ll create `schedule_scan`

@app.post("/scan", response_model=ScanTaskResponse)
async def create_scan(scan_request: ScanRequest, db: Session = Depends(get_db)):
    scan_id = str(uuid4())
    status = "scheduled" if scan_request.scheduled_for else "running"

    # Create a DB record first
    create_scan_record(
        db=db,
        scan_id=scan_id,
        targets=scan_request.targets,
        status=status,
        scheduled_for=scan_request.scheduled_for
    )

    task_args = {"scan_id": scan_id, "targets": scan_request.targets}

    if scan_request.scheduled_for:
        schedule_scan.apply_async(args=[task_args], eta=scan_request.scheduled_for)
    else:
        run_scan.apply_async(args=[task_args])
    logger.info(f"Queuing task for scan {scan_id} with targets: {scan_request.targets}")
    # Send syslog message for scan start
    send_syslog_message(json.dumps({
        "scan_id": scan_id,
        "targets": scan_request.targets,   
        "status": status,
        "scheduled_for": scan_request.scheduled_for.isoformat() if scan_request.scheduled_for else None
        }), db)
    # Return the response with findings
    return ScanTaskResponse(
        id=scan_id,
        targets=scan_request.targets,
        findings=[],  # You can initially set this to an empty list, or populate it after scan completion
        started_at=datetime.datetime.utcnow().isoformat(),
        scheduled_for=scan_request.scheduled_for,
        status=status
    )


@protected_router.get("/scan/{scan_id}", response_class=HTMLResponse)
def scan_detail(scan_id: str, request: Request, user: BasicUser = Depends(get_current_user)):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan.targets = json.loads(scan.targets)
        if scan.raw_data is None:
            scan.raw_data = []
        if isinstance(scan.raw_data, str):
            try:
                scan.raw_data = json.loads(scan.raw_data)
            except json.JSONDecodeError:
                scan.raw_data = []

        # Attach CVE details (severity, remediation) to each vulnerability
        for finding in scan.raw_data:
            if isinstance(finding, dict):
                vulns = finding.get("vulnerabilities", [])
            elif isinstance(finding, list):
                vulns = finding  # or handle as needed
            else:
                vulns = []
                # Now you can process vulns
            for vuln in vulns:
                cve = get_cve_by_id(db, vuln["id"])
                vuln["summary"] = cve.summary if cve and cve.summary else "No summary available"
                vuln["severity"] = cve.severity if cve and cve.severity else "N/A"
                vuln["remediation"] = cve.remediation if cve and cve.remediation else "N/A"
                cvss_score = extract_cvss_score(getattr(cve, "cvss", cve.severity if cve else None))
                vuln["cvss"] = cvss_score if cvss_score is not None else "N/A"
                vuln["criticality"] = (
                    "Critical" if cvss_score and cvss_score >= 9 else
                    "High" if cvss_score and cvss_score >= 7 else
                    "Medium" if cvss_score and cvss_score >= 4 else
                    "Low" if cvss_score and cvss_score > 0 else
                    "N/A"
                )
        scan.raw_data = normalize_scan_data(scan)
        return templates.TemplateResponse("scan_result.html", {
            "request": request,
            "scan": {
                "id": scan.id,
                "targets": scan.targets,
                "status": scan.status,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "raw_data": scan.raw_data
            },
            "scan_id": scan_id,
            "current_user": user,
        })
    finally:
        db.close()

@protected_router.get("/scan/{scan_id}/pdf", response_class=FileResponse)
def get_scan_pdf(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).options(
        joinedload(Scan.findings).joinedload(Finding.cves)
    ).filter(Scan.id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    pdf_file_path = generate_scan_report(scan)

    if not pdf_file_path or not os.path.exists(pdf_file_path):
        raise HTTPException(status_code=404, detail="PDF report not found")

    return FileResponse(pdf_file_path, filename=f"scan_{scan_id}_report.pdf", media_type="application/pdf")

@protected_router.get("/api/report/{agent_id}")
def get_agent_report(agent_id: int, db: Session = Depends(get_db), user: BasicUser = Depends(get_current_user)):
    report = db.query(AgentReport).filter(AgentReport.id == agent_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    
    return JSONResponse(content={
        "hostname": report.hostname,
        "timestamp": str(report.reported_at),
        "packages": [
            {
                "name": pkg.name,
                "version": pkg.version,
                "cves": [{"id": cve.cve_id, "summary": cve.summary} for cve in pkg.cves]
            } for pkg in report.packages
        ]
    })

@app.get("/agent/download")
def download_agent(request: Request):
    base_url = str(request.base_url).rstrip("/")
    
    # Use raw string to avoid escaping issues
    agent_code = f'''
import subprocess
import json
import requests
import socket
import platform
import distro
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

OPENVULNSCAN_API = "{base_url}/agent/report"
OSV_API = "https://api.osv.dev/v1/query"

def get_cves_for_package(package):
    cves = []
    try:
        # Use regular string formatting instead of f-strings for nested dicts
        payload = {{
            "package": {{
                "name": package["name"],
                "version": package["version"]
            }}
        }}
        
        resp = requests.post(OSV_API, json=payload, timeout=10)
        if resp.status_code == 200:
            vulns = resp.json().get("vulns", [])
            for vuln in vulns:
                severity = "Unknown"
                cvss_score = None
                
                if "database_specific" in vuln:
                    cvss_vector = vuln["database_specific"].get("cvss_v3_vector", "")
                    if cvss_vector:
                        score_match = re.search(r"/([0-9]+\\.[0-9]+)/", cvss_vector)
                        if score_match:
                            cvss_score = float(score_match.group(1))
                
                if cvss_score:
                    if cvss_score >= 9.0: severity = "Critical"
                    elif cvss_score >= 7.0: severity = "High"
                    elif cvss_score >= 4.0: severity = "Medium"
                    else: severity = "Low"
                
                cves.append({{
                    "id": vuln.get("id", "UNKNOWN"),
                    "summary": vuln.get("summary", "No summary available"),
                    "severity": severity,
                    "cvss": cvss_score,
                    "details": vuln.get("details", ""),
                    "remediation": "Update to a non-vulnerable version"
                }})
    except Exception as e:
        print("Error querying OSV API: " + str(e))
    return cves

def get_installed_packages():
    try:
        system = platform.system().lower()
        packages = []
        
        if system == "linux":
            distro_name = distro.id().lower()
            if "debian" in distro_name or "ubuntu" in distro_name:
                result = subprocess.run(["dpkg", "-l"], capture_output=True, text=True, check=True)
                for line in result.stdout.split("\\n")[5:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        packages.append({{"name": parts[1], "version": parts[2]}})
            elif "rhel" in distro_name or "centos" in distro_name or "fedora" in distro_name:
                result = subprocess.run(["rpm", "-qa", "--queryformat", "%{{NAME}} %{{VERSION}}\\n"], 
                                     capture_output=True, text=True, check=True)
                for line in result.stdout.split("\\n"):
                    if line:
                        parts = line.split()
                        if len(parts) == 2:
                            packages.append({{"name": parts[0], "version": parts[1]}})
        elif system == "darwin":
            result = subprocess.run(["brew", "list", "--versions"], capture_output=True, text=True, check=True)
            for line in result.stdout.split("\\n"):
                if line:
                    parts = line.split()
                    if len(parts) >= 2:
                        packages.append({{"name": parts[0], "version": parts[1]}})
        return packages
    except Exception as e:
        print("Error getting packages: " + str(e))
        return []

def enrich_packages_with_cves(packages):
    enriched_packages = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_package = {{
            executor.submit(get_cves_for_package, package): package 
            for package in packages
        }}
        for future in future_to_package:
            package = future_to_package[future]
            try:
                cves = future.result()
                enriched_packages.append({{
                    "name": package["name"],
                    "version": package["version"],
                    "cves": cves
                }})
            except Exception as e:
                print("Error enriching package: " + str(e))
                enriched_packages.append({{
                    "name": package["name"],
                    "version": package["version"],
                    "cves": []
                }})
    return enriched_packages

def send_report(packages):
    enriched_packages = enrich_packages_with_cves(packages)
    payload = {{
        "hostname": socket.gethostname(),
        "os_info": platform.system() + " " + platform.release(),
        "packages": enriched_packages
    }}
    
    headers = {{"Content-Type": "application/json"}}
    try:
        response = requests.post(OPENVULNSCAN_API, headers=headers, json=payload)
        print("Report sent, status: " + str(response.status_code))
        if response.status_code != 200:
            print("Error response: " + str(response.text))
    except Exception as e:
        print("Error sending report: " + str(e))

if __name__ == "__main__":
    pkgs = get_installed_packages()
    if pkgs:
        send_report(pkgs)
'''
    return Response(content=agent_code, media_type="text/x-python")

# Register protected routes
app.include_router(protected_router)
app.include_router(dashboard_router)
app.include_router(scan_router)
app.include_router(siem_router) 


@app.exception_handler(HTTPException)
async def auth_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        return RedirectResponse(url="/login")
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

def normalize_scan_data(scan):
    # If it's a full scan, data is already normalized
    if scan.scan_type == "full":
        return scan.raw_data

    # If it's a discovery scan
    if scan.scan_type == "discovery":
        # Convert discovered hosts to findings-like dicts
        return [
            {
                "ip": host.get("ip"),
                "hostname": "",
                "open_ports": [],
                "vulnerabilities": [],
                "services": [],
                "os": "",
                "status": host.get("status", ""),
            }
            for host in scan.raw_data or []
        ]

    # If it's a web scan
    if scan.scan_type == "web":
        # Convert web alerts to findings-like dicts
        return [
            {
                "ip": finding.get("ip", ""),
                "hostname": finding.get("hostname", ""),
                "open_ports": [],
                "vulnerabilities": finding.get("vulnerabilities", []),
                "services": [],
                "os": "",
                "status": "",
            }
            for finding in scan.raw_data or []
        ]
    return []

def extract_cvss_score(cvss_str):
    """
    Extracts the numeric CVSS score from a vector string.
    Examples:
      'CVSS_V3: 9.8 CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' -> 9.8
      '9.8' -> 9.8
    """
    import re
    if not cvss_str:
        return None
    # Try to find a float in the string
    match = re.search(r'([0-9]+\.[0-9]+)', cvss_str)
    if match:
        return float(match.group(1))
    try:
        return float(cvss_str)
    except Exception:
        return None
