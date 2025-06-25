from datetime import datetime
from database.db_manager import SessionLocal
from models.asset import Asset

# OpenVulnScan/services/update_asset.py


def update_asset(ip, os_name, services, web_tech=None):
    db = SessionLocal()
    asset = db.query(Asset).filter_by(ip_address=ip).first()
    if not asset:
        asset = Asset(ip_address=ip)
        db.add(asset)
    asset.os = os_name
    asset.services = services
    if web_tech:
        asset.web_tech = web_tech  # Add this field if you want
    asset.last_scanned = datetime.utcnow()
    db.commit()
    db.close()