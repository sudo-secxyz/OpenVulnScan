# database/db_manager.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import json
import datetime
from models.scan import Scan
from models.agent_report import AgentReport, Package, CVE
from config import DB_PATH
from database.base import Base

# Configure SQLAlchemy
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize the database with required tables"""
    # Instead of manually creating tables, use SQLAlchemy's create_all
    Base

def insert_scan(scan_id, targets, started_at, db=None):
    """Insert a new scan record into the database"""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
    
    try:
        new_scan = Scan(
            id=scan_id,
            targets=targets,
            findings=[],
            started_at=started_at,
            completed_at=None
        )
        db.add(new_scan)
        db.commit()
    finally:
        if close_db:
            db.close()

def update_scan_findings(scan_id, findings, db=None):
    """Update the findings for a scan and mark it complete"""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
    
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.findings = findings
            scan.completed_at = datetime.datetime.utcnow()
            db.commit()
    finally:
        if close_db:
            db.close()

def get_scan(scan_id, db=None):
    """Get details for a single scan"""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
    
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        
        if not scan:
            return None
        
        return {
            "scan_id": scan.id,
            "targets": scan.targets,
            "findings": scan.findings,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
        }
    finally:
        if close_db:
            db.close()

def get_all_scans(db=None):
    """Get all scans ordered by start date"""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
    
    try:
        scans = db.query(Scan).order_by(Scan.started_at.desc()).all()
        
        scans_dict = []
        for scan in scans:
            scans_dict.append({
                "scan_id": scan.id,
                "scan_targets": scan.targets,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
            })
        
        return scans_dict
    finally:
        if close_db:
            db.close()

def debug_scan_findings(scan_id, db=None):
    """Debug function to print scan findings"""
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

def save_agent_report(hostname, packages, db=None):
    """Save agent report using SQLAlchemy models"""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
    
    try:
        # Create agent report
        report = AgentReport(
            hostname=hostname,
            reported_at=datetime.datetime.utcnow()
        )
        db.add(report)
        db.flush()  # To get the ID
        
        # Add packages
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

# Initialize database on import
init_db()