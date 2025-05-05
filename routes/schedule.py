from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from database.db_manager import SessionLocal
from auth.dependencies import  get_current_user, BasicUser
from models.scheduled_scan import ScheduledScan
from models.scan import Scan
from datetime import datetime
from sqlalchemy.orm import joinedload
import json
import logging

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Sceduled Scans
@router.get("/schedule-scan")
def get_schedule_scan(request: Request, user: BasicUser = Depends(get_current_user)):
    db = SessionLocal()
    scans = db.query(ScheduledScan).all()
    db.close()
    return templates.TemplateResponse("schedule_scan.html", {"request": request, "scans": scans, "current_user": user})

@router.post("/schedule-scan")
def post_schedule_scan(
    request: Request,
    target_ip: str = Form(...),
    start_datetime: str = Form(...),
    days: list[str] = Form(default=[]),

):
    db = SessionLocal()

    new_scan = ScheduledScan(
        target_ip=target_ip,
        start_datetime=datetime.fromisoformat(start_datetime),
        days=",".join(days),
        created_at=datetime.utcnow()
    )

    db.add(new_scan)
    db.commit()
    db.close()
    print("Form submitted with:")
    print(f"Target IP:{target_ip}")
    print(f"DateTime:{start_datetime}")

    # Optional: query and log current ScheduledScan entries
    db = SessionLocal()
    for s in db.query(ScheduledScan).all():
        print(f"[DEBUG] Scheduled: {s.target_ip} at {s.start_datetime}, days: {s.days}")
    db.close()
    return RedirectResponse("/schedule-scan", status_code=303)

@router.post("/delete-scan/{scan_id}")
def delete_scheduled_scan(scan_id: int, user: BasicUser = Depends(get_current_user)):
    db = SessionLocal()
    scan = db.query(ScheduledScan).filter(ScheduledScan.id == scan_id).first()
    if scan:
        db.delete(scan)
        db.commit()
    db.close()
    return RedirectResponse("/schedule-scan", status_code=303)

@router.get("/edit-scan/{scan_id}", response_class=HTMLResponse)
def edit_scheduled_scan(request: Request, scan_id: int, user: BasicUser = Depends(get_current_user)):
    db = SessionLocal()
    scan = db.query(ScheduledScan).filter(ScheduledScan.id == scan_id).first()
    db.close()
    return templates.TemplateResponse("edit_scan.html", {"request": request, "scan": scan, "current_user": user})

@router.post("/edit-scan/{scan_id}")
def update_scheduled_scan(
    scan_id: int,
    target_ip: str = Form(...),
    start_datetime: str = Form(...),
    days: list[str] = Form(default=[])
):
    db = SessionLocal()
    scan = db.query(ScheduledScan).filter(ScheduledScan.id == scan_id).first()
    if scan:
        scan.target_ip = target_ip
        scan.start_datetime = datetime.fromisoformat(start_datetime)
        scan.days = ",".join(days)
        db.commit()
    db.close()
    return RedirectResponse("/schedule-scan", status_code=303)

@router.get("/scans", response_class=HTMLResponse)
def view_scan_history(request: Request, user: BasicUser = Depends(get_current_user)):
    db = SessionLocal()
    results = db.query(Scan).order_by(Scan.completed_at.desc()).all()
    db.close()
    return templates.TemplateResponse("scan_history.html", {"request": request, "results": results, "current_user": user})

@router.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: str, user: BasicUser = Depends(get_current_user)):
    db = SessionLocal()
    try:
        result = db.query(Scan).options(joinedload(Scan.findings)).filter(Scan.id == scan_id).first()
        if not result:
            return HTMLResponse(f"<h1>Scan ID {scan_id} not found</h1>", status_code=404)

        # Deserialize raw_data for each finding
        for finding in result.findings:
            logger.info(f"Raw data before deserialization: {finding.raw_data}")
            if isinstance(finding.raw_data, str):
                try:
                    finding.raw_data = json.loads(finding.raw_data)
                    logger.info(f"Deserialized raw_data: {finding.raw_data}")
                except json.JSONDecodeError:
                    finding.raw_data = {}  # Default to an empty dictionary if deserialization fails
                    logger.error(f"Failed to deserialize raw_data for finding {finding.id}")
    finally:
        db.close()

    return templates.TemplateResponse("scan_detail.html", {"request": request, "result": result, "current_user": user})