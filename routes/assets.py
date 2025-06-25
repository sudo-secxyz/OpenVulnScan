# routes/assets.py
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from database.db_manager import SessionLocal, get_db
from models.scan import Scan
from models.cve import CVE
from models.scheduled_scan import ScheduledScan
from models.agent_report import AgentReport
from models.finding import Finding
from models.web_alert import WebAlert
from models.asset import Asset
from fastapi.responses import HTMLResponse
from auth.dependencies import get_current_user, BasicUser
from sqlalchemy.orm import selectinload, joinedload, Session
from config import setup_logging

logger = setup_logging()

import ast
import json

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/assets")
def get_assets(request: Request, user: BasicUser = Depends(get_current_user)):
    db = SessionLocal()
    
    scans = db.query(Scan).options(joinedload(Scan.findings)).all()
    scheduled_scans = db.query(ScheduledScan).all()

    asset_dict = {}

    for scan in scans:
        targets = scan.targets
        # Always decode JSON string to list
        if isinstance(targets, str):
            try:
                targets = json.loads(targets)
            except Exception:
                targets = [targets]
        # Now targets is a list of IPs
        for target in targets:
            if not target or not isinstance(target, str) or target.strip() in {"", "[", "]", ".", '"', "'"}:
                continue
            if target not in asset_dict:
                asset = db.query(Asset).filter(Asset.ip_address == target).first()
                asset_dict[target] = {
                    "scans": [],
                    "scheduled": [],
                    "hostname": asset.hostname if asset else "",
                    "last_scanned": asset.last_scanned if asset else None
                }
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

@router.get("/assets/{ip_address}", response_class=HTMLResponse)
def asset_detail(ip_address: str, request: Request, user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.ip_address == ip_address).first()
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
        })
    finally:
        db.close()