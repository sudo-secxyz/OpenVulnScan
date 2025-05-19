from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database.base import Base

class WebAlert(Base):
    __tablename__ = "web_alerts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    name = Column(String, nullable=False)
    risk = Column(String)
    description = Column(String)
    solution = Column(String)
    reference = Column(String)

    scan = relationship("Scan", back_populates="web_alerts")

