# models/scheduled_scan.py
from sqlalchemy import Column, Integer, String, DateTime
from database.base import Base
from datetime import datetime

class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id = Column(Integer, primary_key=True, index=True)
    target_ip = Column(String, nullable=False)  # Comma-separated list of IPs
    start_datetime = Column(DateTime, nullable=False)
    days = Column(String, nullable=True)  # Comma-separated list like "mon,wed,fri"
    created_at = Column(DateTime, default=datetime.utcnow)

    def get_targets(self):
        if isinstance(self.target_ip, str):
            return [self.target_ip]
        return self.target_ip
