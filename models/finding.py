# models/finding.py
from sqlalchemy import Column, String, Integer, ForeignKey, Text, DateTime, JSON, Index
from sqlalchemy.orm import relationship
from models.cve import CVE
import datetime
from database.base import Base

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    ip_address = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    raw_data = Column(Text, nullable=True)
    description = Column(Text)  # Add description field
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    severity = Column(String, nullable=True)  # e.g., "low", "medium", "high"
    
    # Use string-based reference to avoid circular import
    cves = relationship("CVE", back_populates="finding", cascade="all, delete-orphan")

    scan = relationship("Scan", back_populates="findings")
    __table_args__ = (
        Index('ix_findings_scan_id', 'scan_id'),
    )
