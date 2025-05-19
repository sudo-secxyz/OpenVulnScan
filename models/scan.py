# models/scan.py
from sqlalchemy import Column, String, JSON, DateTime, Text, ARRAY, Integer, ForeignKey
from sqlalchemy.orm import relationship
from database.base import Base
import datetime
from enum import Enum as PyEnum
# models/scan.py
from models.scan_target import ScanTarget
from models.finding import Finding


class ScanStatus(PyEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, index=True)
    targets = Column(String)  # List of target
    scan_type = Column(String, nullable=False)  # e.g., 'nmap', 'zap', 'discovery'
    raw_data = Column(JSON, nullable=True)  # Store consolidated scan results
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String, default="pending")
    started_at = Column(DateTime, default=datetime.datetime.utcnow(),nullable=True)
    scheduled_for = Column(DateTime, nullable=True)
   # Store scan results in JSON format
    

    # Existing relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete")
    scan_targets = relationship("ScanTarget", back_populates="scan", cascade="all, delete")

    # New relationships
    discovered_hosts = relationship("DiscoveryHost", back_populates="scan", cascade="all, delete")
    web_alerts = relationship("WebAlert", back_populates="scan", cascade="all, delete")
    tasks = relationship("ScanTask", back_populates="scan", cascade="all, delete")


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    name = Column(String, nullable=False)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="tasks")