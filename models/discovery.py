from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database.base import Base

class DiscoveryHost(Base):
    __tablename__ = "discovery_hosts"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, nullable=False)
    status = Column(String, default="up")
    scan_id = Column(Integer, ForeignKey("scans.id"))

    scan = relationship("Scan", back_populates="discovered_hosts")
