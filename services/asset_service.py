# services/asset_service.py
from sqlalchemy.orm import Session
from database.db_manager import SessionLocal
from models.scan import Scan
from models.scheduled_scan import ScheduledScan
from models.agent_report import AgentReport
from models.asset import Asset
from datetime import datetime

def get_all_assets():
    db: Session = SessionLocal()
    assets = set()

    # Collect from scans
    for scan in db.query(Scan).all():
        if scan.targets:
            if isinstance(scan.targets, str):
                try:
                    import json
                    targets = json.loads(scan.targets)
                except:
                    targets = [scan.targets]
                for target in targets:
                    assets.add(target)

    # Collect from scheduled scans
    for scan in db.query(ScheduledScan).all():
        assets.add(scan.target_ip)

    # Collect from agent scans
    for scan in db.query(AgentReport).all():
        assets.add(scan.target_ip)

    db.close()
    return list(assets)

def ensure_asset_exists(ip_address: str, hostname: str = "", last_scanned=None):
    db = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.ip_address == ip_address).first()
        if not asset:
            if last_scanned is None:
                last_scanned = datetime.utcnow()
            asset = Asset(ip_address=ip_address, hostname=hostname, last_scanned=last_scanned)
            db.add(asset)
            db.commit()
            db.refresh(asset)
        else:
            if last_scanned:
                asset.last_scanned = last_scanned
            db.commit()
        return asset.id  # <-- Return just the ID
    finally:
        db.close()
