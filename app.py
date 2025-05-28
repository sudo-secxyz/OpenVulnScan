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
        # Deserialize targets
        scan.targets = json.loads(scan.targets)
        # Ensure raw_data is initialized
        if scan.raw_data is None:
            scan.raw_data = []

        # Deserialize raw_data if it's a JSON string
        if isinstance(scan.raw_data, str):
            try:
                scan.raw_data = json.loads(scan.raw_data)
            except json.JSONDecodeError:
                logger.error(f"Failed to deserialize raw_data for scan {scan_id}")
                scan.raw_data = []

        logger.debug(f"Processed raw_data for scan {scan_id}: {scan.raw_data}")

        # Iterate over findings in raw_data
        for finding in scan.raw_data:
            if isinstance(finding, dict):  # Ensure each finding is a dictionary
                for vuln in finding.get("vulnerabilities", []):
                    cve = get_cve_by_id(db, vuln["id"])
                    logger.debug(f"Fetched CVE {vuln['id']} with summary: {cve.summary if cve else 'Not found'}")
                    vuln["summary"] = cve.summary if cve and cve.summary else "No summary available"

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

@app.get("/agent/download", response_class=Response)
def download_agent(request: Request):
    base_url = str(request.base_url).rstrip("/")
    agent_code = f'''
import subprocess
import json
import requests
import socket
import platform
import distro

OPENVULNSCAN_API = "{base_url}/agent/report"

def get_installed_packages():
    try:
        system = platform.system().lower()
        packages = []

        if system == "linux":
            distro_name = distro.id().lower()
            if "debian" in distro_name or "ubuntu" in distro_name:
                packages = get_debian_packages()
            elif "kali" in distro_name:
                packages = get_debian_packages()  # Kali is based on Debian
            elif "rhel" in distro_name or "centos" in distro_name or "fedora" in distro_name:
                packages = get_redhat_packages()
            else:
                print(f"Unsupported Linux distribution: {{distro_name}}")
                
        elif system == "darwin":
            packages = get_macos_packages()
        elif system == "windows":
            packages = get_windows_packages()
        else:
            print(f"Unsupported operating system: {{system}}")
        return packages
    except Exception as e:
        print(f"Error detecting system packages: {{e}}")
        return []


def get_debian_packages():
    try:
        result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, check=True)
        packages = []
        for line in result.stdout.split('\\n')[5:]:
            parts = line.split()
            if len(parts) >= 3:
                packages.append({{"name": parts[1], "version": parts[2]}})
        return packages
    except Exception as e:
        print(f"Error getting Debian/Ubuntu packages: {{e}}")
        return []

def get_redhat_packages():
    try:
        result = subprocess.run(['rpm', '-qa', '--queryformat', '%{{NAME}} %{{VERSION}}\\n'], capture_output=True, text=True, check=True)
        packages = []
        for line in result.stdout.split('\\n'):
            parts = line.split()
            if len(parts) == 2:
                packages.append({{"name": parts[0], "version": parts[1]}})
        return packages
    except Exception as e:
        print(f"Error getting Red Hat-based packages: {{e}}")
        return []

def get_macos_packages():
    try:
        result = subprocess.run(['brew', 'list', '--versions'], capture_output=True, text=True, check=True)
        packages = []
        for line in result.stdout.split('\\n'):
            parts = line.split()
            if len(parts) >= 2:
                packages.append({{"name": parts[0], "version": parts[1]}})
        return packages
    except Exception as e:
        print(f"Error getting macOS packages: {{e}}")
        return []

def get_windows_packages():
    try:
        result = subprocess.run(['wmic', 'product', 'get', 'name,version'], capture_output=True, text=True, check=True)
        packages = []
        for line in result.stdout.split('\\n')[1:]:
            parts = line.split()
            if len(parts) >= 2:
                packages.append({{"name": ' '.join(parts[:-1]), "version": parts[-1]}})
        return packages
    except Exception as e:
        print(f"Error getting Windows packages: {{e}}")
        return []

def send_report(packages):
    payload = {{"hostname": socket.gethostname(), "packages": packages}}
    headers = {{"Content-Type": "application/json"}}
    response = requests.post(OPENVULNSCAN_API, headers=headers, json=payload)
    print(f"Report sent, status: {{response.status_code}}, body: {{response.text}}")

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


@app.exception_handler(HTTPException)
async def auth_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        return RedirectResponse(url="/login")
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
