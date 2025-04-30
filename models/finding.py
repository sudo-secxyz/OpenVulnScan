from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.orm import relationship
from database.base import Base

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    description = Column(String)
    scan_id = Column(String, ForeignKey("scans.id"))

    scan = relationship("Scan", back_populates="scan_findings")
