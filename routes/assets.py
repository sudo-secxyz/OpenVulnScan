# routes/assets.py
from fastapi import APIRouter, Request, Depends, HTTPException, Form, Query
from fastapi.templating import Jinja2Templates
from database.db_manager import SessionLocal, get_db
from models.scan import Scan
from models.cve import CVE
from models.scheduled_scan import ScheduledScan
from models.agent_report import AgentReport
from models.finding import Finding
from models.web_alert import WebAlert
from models.asset import Asset
from fastapi.responses import HTMLResponse, RedirectResponse
from auth.dependencies import get_current_user, BasicUser
from sqlalchemy.orm import selectinload, joinedload, Session
from config import setup_logging
from services.tag_service import assign_tag_to_asset, remove_tag_from_asset
from models.tag import Tag


logger = setup_logging()

import ast
import json

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/assets")
def get_assets(request: Request, user: BasicUser = Depends(get_current_user), tag_id: int = Query(None)):
    db = SessionLocal()
    search = request.query_params.get("search", "").strip().lower()

    # Query all assets
    assets = db.query(Asset).all()
    asset_dict = {}

    for asset in assets:
        if search:
            if search not in asset.ip_address.lower() and (not asset.hostname or search not in asset.hostname.lower()):
                continue
        asset_dict[asset.ip_address] = {
            "hostname": asset.hostname,
            "last_scanned": asset.last_scanned,
            "scans": [],
            "scheduled": []
        }

    # Optionally, attach scans and scheduled scans to each asset
    scans = db.query(Scan).options(joinedload(Scan.findings)).all()
    for scan in scans:
        targets = scan.targets
        if isinstance(targets, str):
            try:
                targets = json.loads(targets)
            except Exception:
                targets = [targets]
        for target in targets:
            if target in asset_dict:
                asset_dict[target]["scans"].append(scan)

    scheduled_scans = db.query(ScheduledScan).all()
    for sscan in scheduled_scans:
        ip = sscan.target_ip
        if ip in asset_dict:
            asset_dict[ip]["scheduled"].append(sscan)

    all_tags = db.query(Tag).all()
    if tag_id:
        assets = db.query(Asset).join(Asset.tags).filter(Tag.id == tag_id).all()
    else:
        assets = db.query(Asset).all()

    db.close()
    return templates.TemplateResponse("assets.html", {
        "request": request,
        "assets": asset_dict,
        "current_user": user,
        "search": search,
        "all_tags": all_tags,
        "selected_tag": tag_id
    })

from schemas.finding import FindingSchema
from models.finding import Finding

@router.get("/finding/{finding_id}", response_model=FindingSchema)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@router.get("/assets/{ip_address}", response_class=HTMLResponse)
def asset_detail(ip_address: str, request: Request, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.ip_address == ip_address).first()
        all_tags = db.query(Tag).all()
        if not asset:
            return HTMLResponse(f"<h2>Asset {ip_address} not found</h2>", status_code=404)

        scans = db.query(Scan).options(joinedload(Scan.findings)).filter(Scan.targets.like(f'%{ip_address}%')).order_by(Scan.started_at.desc()).all()
        agent_reports = db.query(AgentReport).filter(AgentReport.target_ip == ip_address).order_by(AgentReport.created_at.desc()).all()
        scan_ids = [scan.id for scan in scans]
        web_alerts = db.query(WebAlert).filter(WebAlert.scan_id.in_(scan_ids)).order_by(WebAlert.id.desc()).all()

        # Attach CVE details to each finding in each scan
        for scan in scans:
            if scan.raw_data and isinstance(scan.raw_data, str):
                try:
                    scan.raw_data = json.loads(scan.raw_data)
                except Exception:
                    scan.raw_data = []
            if scan.raw_data:
                for finding in scan.raw_data:
                    if not isinstance(finding, dict):
                        logger.error(f"Skipping finding because it is not a dict: {finding}")
                        continue
                    # Attach OS info if present
                    os_info = finding.get("os") or finding.get("os_info") or "Unknown"
                    finding["os_info"] = os_info

                    # Attach CVE details to each vulnerability
                    for vuln in finding.get("vulnerabilities", []):
                        cve_id = vuln.get("cve_id")
                        cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
                        vuln["summary"] = cve.summary if cve and cve.summary else "No summary available"
                        vuln["description"] = cve.description if cve and cve.description else vuln.get("description", "")
                        vuln["severity"] = vuln.get("severity", cve.severity if cve else "N/A")
                        vuln["remediation"] = vuln.get("remediation", cve.remediation if cve else "No remediation available")
                        vuln["port"] = vuln.get("port", finding.get("port", "N/A"))

        return templates.TemplateResponse("asset_detail.html", {
            "request": request,
            "asset": asset,
            "scans": scans,
            "agent_reports": agent_reports,
            "web_alerts": web_alerts,
            "current_user": user,
            "all_tags": all_tags
        })
    finally:
        db.close()

@router.post("/assets/{ip_address}/tags/add")
def add_tag(ip_address: str, tag_id: int = Form(...), db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.ip_address == ip_address).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    assign_tag_to_asset(db, asset.id, tag_id)
    return RedirectResponse(url=f"/assets/{ip_address}", status_code=303)

@router.post("/assets/{ip_address}/tags/{tag_id}/delete")
def delete_tag(ip_address: str, tag_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.ip_address == ip_address).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    remove_tag_from_asset(db, asset.id, tag_id)
    return RedirectResponse(url=f"/assets/{ip_address}", status_code=303)




