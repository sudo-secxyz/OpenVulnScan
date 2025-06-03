# models/agent_report.py
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database.base import Base

class AgentReport(Base):
    __tablename__ = "agent_reports"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey('assets.id'))
    target_ip = Column(String)
    hostname = Column(String)
    created_at = Column(DateTime)
    os_info = Column(String)
    reported_at = Column(DateTime)  # <-- ADD THIS LINE
    packages = relationship("Package", back_populates="report")

    asset = relationship("Asset", back_populates="agent_reports")

