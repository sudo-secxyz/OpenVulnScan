from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.orm import relationship
from database.base import Base

class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    scan_id = Column(String, ForeignKey("scans.id"))

    scan = relationship("Scan", back_populates="scan_targets")
