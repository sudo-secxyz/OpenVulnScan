# models/scan.py
from sqlalchemy import Column, String, JSON, DateTime
from sqlalchemy.orm import relationship
from database.base import Base
import datetime

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(String, primary_key=True)
    targets = Column(JSON)  # For storing list of targets
    findings = Column(JSON)  # For storing findings
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    # If you have relationships with other tables
    # targets_relation = relationship("ScanTarget", back_populates="scan")
    # findings_relation = relationship("Finding", back_populates="scan")