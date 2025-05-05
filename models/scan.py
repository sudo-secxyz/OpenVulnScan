# models/scan.py
from sqlalchemy import Column, String, JSON, DateTime, Text, ARRAY
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

    id = Column(String, primary_key=True)
    status = Column(String, default='pending')
    targets = Column(JSON)  # raw list, e.g., ["192.168.1.1"]
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    scheduled_for = Column(DateTime, nullable=True)

    # relationships
    scan_targets = relationship("ScanTarget", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", cascade="all, delete-orphan")  # Removed backref
