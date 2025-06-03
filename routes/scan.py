#routes/scan.py
from fastapi import APIRouter, Request, Form, Depends
from sqlalchemy.orm import Session
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_303_SEE_OTHER
from utils.tasks import run_nmap_discovery, run_nmap_scan, run_zap_scan
from database.db_manager import SessionLocal, get_db
from services.asset_service import ensure_asset_exists
from models.scan import Scan, ScanTask
from models.schemas import ScanCreate
from config import ZAP_RESULTS_DIR
from uuid import uuid4
import datetime
import json
import os
import logging




router = APIRouter()
templates = Jinja2Templates(directory="templates")

from auth.dependencies import get_current_user, BasicUser


from urllib.parse import urlparse, urlunparse

def normalize_url(target: str) -> str:
    """Ensure the target URL includes a valid scheme."""
    parsed = urlparse(target)
    if not parsed.scheme:
        # Default to http if no scheme is provided
        return urlunparse(("http", parsed.netloc or parsed.path, "", "", "", ""))
    return target

# routes/scans.py
@router.get("/create-scan")
async def get_create_scan_form(request: Request, user: BasicUser = Depends(get_current_user)):
    return templates.TemplateResponse("create_scan.html", {"request": request, "current_user": user})


@router.post("/create-scan")
async def create_scan(
    request: Request,
    target: str = Form(...),
    scan_type: str = Form(...),
    db: Session = Depends(get_db),
    user: BasicUser = Depends(get_current_user)
):
    scan_id = str(uuid4())
    # Ensure targets is a Python list
    if isinstance(target, str):
        targets = [target]
    else:
        targets = target
    serialized_targets = json.dumps(targets)
    # Save serialized_targets to Scan.targets
    primary_ip = targets[0] if isinstance(targets, list) and targets else targets
    asset = ensure_asset_exists(primary_ip)
    scan = Scan(
        id=scan_id,
        asset_id = asset,
        targets=serialized_targets,  # Save as a JSON string
        status="pending",
        created_at=datetime.datetime.utcnow(),
        scan_type=scan_type
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    if scan_type == "discovery":
        task = ScanTask(scan_id=scan_id, name="Discovery", status="pending")
        db.add(task)
        db.commit()
        run_nmap_discovery.delay(scan_id, target)

    elif scan_type == "web":
        # Normalize the target URL
        normalized_target = normalize_url(target)
        
        # Generate the ZAP output path
        zap_output_path = os.path.join(ZAP_RESULTS_DIR, f"{scan_id}.json")
        task = ScanTask(scan_id=scan_id, name="WebScan", status="pending")
        db.add(task)
        db.commit()
        # Log and validate the target URL

        if not normalized_target.startswith(("http://", "https://")):
            raise ValueError(f"Invalid target URL: {normalized_target}. Must include http:// or https://")
        # Pass the normalized target as the target_url parameter
        run_zap_scan.delay(scan_id, zap_output_path, target_url=normalized_target)

    elif scan_type == "full":
        task = ScanTask(scan_id=scan_id, name="FullScan", status="pending")
        db.add(task)
        db.commit()
        run_nmap_scan.delay(scan_id, target)

    return templates.TemplateResponse("scan_queued.html", {"request": request, "scan": scan, "current_user": user})
