# services/asset_service.py
from sqlalchemy.orm import Session
from database.db_manager import SessionLocal
from models.scan import Scan
from models.scheduled_scan import ScheduledScan
from models.agent_report import AgentReport

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
