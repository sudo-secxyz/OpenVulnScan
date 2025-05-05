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
    finding_id = Column(Integer, ForeignKey('findings.id'))
    severity = Column(String, nullable=True)  # e.g., "low", "medium", "high"

    package_id = Column(Integer, ForeignKey("packages.id"))  # This is correct
    package = relationship("Package", back_populates="cves")
    finding = relationship("Finding", back_populates="cves")
