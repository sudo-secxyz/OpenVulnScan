# routes/assets.py
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from database.db_manager import SessionLocal, get_db
from models.scan import Scan
from models.scheduled_scan import ScheduledScan
from auth.dependencies import get_current_user, BasicUser
from sqlalchemy.orm import selectinload, joinedload, Session


router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/assets")
def get_assets(request: Request, user: BasicUser = Depends(get_current_user)):
    db = SessionLocal()
    
    scans = db.query(Scan).options(joinedload(Scan.findings)).all()
    scheduled_scans = db.query(ScheduledScan).all()

    asset_dict = {}

    for scan in scans:
        for target in scan.targets:
            if target not in asset_dict:
                asset_dict[target] = {"scans": [], "scheduled": []}
            asset_dict[target]["scans"].append(scan)

    for sscan in scheduled_scans:
        ip = sscan.target_ip
        if ip not in asset_dict:
            asset_dict[ip] = {"scans": [], "scheduled": []}
        asset_dict[ip]["scheduled"].append(sscan)

    db.close()
    return templates.TemplateResponse("assets.html", {
        "request": request,
        "assets": asset_dict,
        "current_user": user,
    })

from schemas.finding import FindingSchema
from models.finding import Finding

@router.get("/finding/{finding_id}", response_model=FindingSchema)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding