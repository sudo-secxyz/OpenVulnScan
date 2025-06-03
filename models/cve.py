# models/cve.py
from sqlalchemy import Column, String, Integer, ForeignKey, Text
from sqlalchemy.orm import relationship
from database.base import Base  # Import from a single source

class CVE(Base):
    __tablename__ = "cves"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)

    cve_id = Column(String, nullable=False)
    summary = Column(Text, nullable=True)
    severity = Column(String, nullable=True)  # e.g., "low", "medium", "high"
    remediation = Column(Text, nullable=True) # <-- Add this line
    finding_id = Column(Integer, ForeignKey('findings.id'))
    package_id = Column(Integer, ForeignKey("packages.id"))

    package = relationship("Package", back_populates="cves")
    finding = relationship("Finding", back_populates="cves")
