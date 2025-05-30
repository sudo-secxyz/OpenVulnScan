from sqlalchemy import Column, Integer, String, Boolean
from database.base import Base

class SIEMConfig(Base):
    __tablename__ = "siem_config"

    id = Column(Integer, primary_key=True, index=True)
    enabled = Column(Boolean, default=False)
    host = Column(String, nullable=False)
    port = Column(Integer, default=514)
    protocol = Column(String, default="udp")  # Options: 'udp' or 'tcp'
    format = Column(String, default="plain")  # Options: 'plain', 'cef', etc.
