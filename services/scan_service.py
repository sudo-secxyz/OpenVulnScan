# services/scan_service.py
import uuid
import datetime
import json
from fastapi import BackgroundTasks
from sqlalchemy.orm import Session
from config import setup_logging
from database.ops import (
    insert_scan,
    get_scan,
    update_scan_findings,
    SessionLocal
)
from models.finding import Finding
from models.cve import CVE
from models.scan import Scan
from models.asset import Asset, Vulnerability
from models.schemas import ScanRequest, ScanResult
from scanners.nmap_runner import NmapRunner
from datetime import datetime
import pytz
from utils.settings import get_system_timezone

logger = setup_logging()

tz = pytz.timezone(get_system_timezone())
def start_scan_task(req: ScanRequest, background_tasks: BackgroundTasks = None) -> ScanResult:
    scan_id = str(uuid.uuid4())
    
    now = datetime.now(tz)
    
    
    # Insert scan metadata (with correct ID)
    insert_scan(scan_id, req.targets, now)
    
    if background_tasks:
        logger.debug(f"Queueing scan task {scan_id} for targets: {req.targets}")
        background_tasks.add_task(run_scan, scan_id, req.targets)

    return ScanResult(
        id=scan_id,
        targets=req.targets,
        findings=[],
        started_at=now,
        completed_at=None
    )


def run_scan(scan_id: str, targets: list):
    """Run a scan and update findings and asset data"""
    db = SessionLocal()
    try:
        update_scan_status(scan_id, 'queued')
        logger.info(f"Running scan {scan_id} on targets: {targets}")
        
        scanner = NmapRunner(targets)
        findings = scanner.run()
        if isinstance(findings, list) and findings and isinstance(findings[0], dict):
            cleaned_findings = clean_findings(findings)
            db_scan = db.query(Scan).filter(Scan.id == scan_id).first()

            if db_scan:
                orm_findings = []
                for finding in cleaned_findings:
                    for vuln in finding["vulnerabilities"]:
                        orm_findings.append(Finding(
                        scan_id=scan_id,
                        ip_address=finding["ip"],  # Use 'ip_address' here instead of 'ip'
                        hostname=finding["hostname"],
                        raw_data=json.dumps(finding),  # Optionally store raw data if necessary
                        created_at=datetime.now(tz) # Or use the scan time
                    ))

                db_scan.findings = orm_findings
                db.commit()


        

        logger.debug(f"Scan {scan_id} findings: {json.dumps(cleaned_findings, indent=2)}")

            

        update_scan_status(scan_id, 'completed')
        logger.info(f"Scan {scan_id} completed successfully")
        return cleaned_findings
    except Exception as e:
        update_scan_status(scan_id, 'failed')
        logger.error(f"Error during scan {scan_id}: {str(e)}", exc_info=True)
        return None
    finally:
        db.close()

def update_scan_status(scan_id: str, status: str):
    """Update the status of a scan in the database"""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = status
            if status == 'completed':
                scan.completed_at = datetime.now(tz)
            db.commit()
    finally:
        db.close()

def get_scan_details(scan_id: str):
    """Get a specific scan record including deserialized findings"""
    return get_scan(scan_id)

def clean_findings(findings):
    """Sanitize and normalize scan result fields"""
    cleaned = []
    for finding in findings:
        cleaned.append({
            "ip": finding.get("ip", "").strip(),
            "hostname": finding.get("hostname", "").strip(),
            "open_ports": [
                {
                    "port": port.get("port", "").strip(),
                    "protocol": port.get("protocol", "").strip(),
                    "service": port.get("service", "").strip()
                }
                for port in finding.get("open_ports", [])
            ],
            "vulnerabilities": [
                {
                    "id": vuln.get("id", "").strip(),
                    "description": vuln.get("description", "").strip()
                }
                for vuln in finding.get("vulnerabilities", [])
            ]
        })
    return cleaned

def update_asset(ip_address: str, hostname: str, vulnerabilities: list[dict]):
    """Update asset and associate new vulnerabilities"""
    db = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.ip_address == ip_address).first()

        if not asset:
            asset = Asset(
                ip_address=ip_address,
                hostname=hostname,
                last_scanned=datetime.now(tz)
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)
            logger.debug(f"Created new asset: {ip_address}")
        else:
            asset.hostname = hostname
            asset.last_scanned = datetime.now(tz)
            logger.debug(f"Updated existing asset: {ip_address}")

        for vuln in vulnerabilities:
            vuln_id = vuln.get("id") or str(uuid.uuid4())
            description = vuln.get("description", "No description provided")

            vulnerability = Vulnerability(
                asset_id=asset.id,
                vulnerability_id=vuln_id,
                description=description
            )
            db.add(vulnerability)

        db.commit()
        logger.info(f"Committed {len(vulnerabilities)} vulnerabilities to asset {ip_address}")

    except Exception as e:
        db.rollback()
        logger.error(f"Error updating asset {ip_address}: {str(e)}", exc_info=True)
        raise
    finally:
        db.close()
