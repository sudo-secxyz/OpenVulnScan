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


# models/package.py
class Package(Base):
    __tablename__ = "packages"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("agent_reports.id"))
    name = Column(String)
    version = Column(String)

    report = relationship("AgentReport", back_populates="packages")
    cves = relationship("CVE", back_populates="package")


# models/cve.py
class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String)
    summary = Column(String)
    severity = Column(String)

    package_id = Column(Integer, ForeignKey("packages.id"))
    package = relationship("Package", back_populates="cves")
