# models/agent_report.py
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from database.base import Base
from datetime import datetime

class AgentReport(Base):
    __tablename__ = "agent_reports"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String)
    reported_at = Column(DateTime, default=datetime.utcnow)
    os_info = Column(String)
    packages = relationship("Package", back_populates="report")

