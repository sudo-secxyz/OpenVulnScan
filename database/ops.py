# database/ops.py

import json
import uuid
import datetime
import logging

from sqlalchemy.orm import Session
from database.db_manager import SessionLocal
from services.asset_service import ensure_asset_exists
from models.asset import Asset, Vulnerability
from models.scan import Scan
from models.finding import Finding
from models.agent_report import AgentReport
from models.package import Package
from models.cve import CVE

# Logger setup
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

def init_db():
    from database.db_manager import Base, engine
    import models  # Ensure models are loaded
    Base.metadata.create_all(bind=engine)

def insert_scan(scan_id: str, targets: list, started_at: datetime.datetime, scan_type: str):
    db = SessionLocal()
    try:
        # Ensure targets is a list, whether it's passed as a string or already a list
        if isinstance(targets, str):
            try:
                targets = json.loads(targets)
                if not isinstance(targets, list):
                    raise ValueError("Targets must be a list of strings")
            except (json.JSONDecodeError, ValueError) as e:
                logger.error(f"Failed to decode targets: {e}")
                targets = []
        elif not isinstance(targets, list):
            logger.error("Targets is not a list or a valid JSON string")
            targets = []
        primary_ip = targets[0] if isinstance(targets, list) and targets else targets
        asset= ensure_asset_exists(primary_ip)
        new_scan = Scan(
            id=scan_id,
            asset_id=asset,
            targets=json.dumps(targets),
            started_at=started_at,
            completed_at=None,
            scan_type=scan_type,  # <-- Use it here
            status='queued'
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)
        return new_scan
    finally:
        db.close()



def update_scan_findings(scan_id: str, findings: list[dict], db: Session = None):
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise Exception(f"Scan with ID {scan_id} not found")
        
        # Ensure findings is a list before saving
        if isinstance(findings, str):
            try:
                findings = json.loads(findings)
            except json.JSONDecodeError:
                logger.error(f"Error decoding findings for scan {scan_id}")
                findings = []

        if isinstance(findings, list) and all(isinstance(f, dict) for f in findings):
            scan.findings = json.dumps(findings)
            db.commit()
            logger.info(f"Findings for scan {scan_id} saved to the database")
        else:
            logger.error(f"Invalid findings format for scan {scan_id}")
    finally:
        if close_db:
            db.close()


def get_scan(scan_id: str):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if scan and isinstance(scan.findings, str):
            try:
                scan.findings = json.loads(scan.findings)
            except json.JSONDecodeError:
                logger.error(f"Error decoding findings for scan {scan_id}")
                scan.findings = []
        return scan
    finally:
        db.close()

def get_cve_by_id(db: Session, cve_id: str):
    return db.query(CVE).filter(CVE.cve_id == cve_id).first()


def get_all_scans(db: Session = None):
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
        return [{
            "scan_id": scan.id,
            "scan_targets": scan.target,
            "started_at": scan.created_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
        } for scan in scans]
    finally:
        if close_db:
            db.close()

def debug_scan_findings(scan_id: str, db: Session = None):
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            print(f"DEBUG findings from DB: {scan.findings}")
            return scan.findings
        return None
    finally:
        if close_db:
            db.close()

def save_agent_report(hostname: str, packages: list[dict], db: Session = None):
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        report = AgentReport(
            hostname=hostname,
            reported_at=datetime.datetime.utcnow()
        )
        db.add(report)
        db.flush()

        for pkg_data in packages:
            package = Package(
                name=pkg_data.get("name"),
                version=pkg_data.get("version"),
                report_id=report.id
            )
            db.add(package)

        db.commit()
        return report.id
    finally:
        if close_db:
            db.close()
