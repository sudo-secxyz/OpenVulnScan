from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database.base import Base

class Package(Base):
    __tablename__ = "packages"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("agent_reports.id"))
    name = Column(String)
    version = Column(String)

    report = relationship("AgentReport", back_populates="packages")
    cves = relationship("CVE", back_populates="package")
