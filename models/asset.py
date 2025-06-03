# models/asset.py
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from database.base import Base

from datetime import datetime

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey('assets.id'))
    vulnerability_id = Column(String)
    description = Column(String)

    asset = relationship("Asset", back_populates="vulnerabilities")

class Asset(Base):
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String, nullable=False)
    hostname = Column(String, nullable=False, default='')
    last_scanned = Column(DateTime, nullable=False)
    
    vulnerabilities = relationship("Vulnerability", back_populates="asset")
    scans = relationship("Scan", back_populates="asset")
    
    agent_reports = relationship("AgentReport", back_populates="asset")
