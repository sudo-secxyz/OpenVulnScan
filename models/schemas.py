# models/schemas.py

from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from models.finding import Finding  # Assuming Finding is defined in models/finding.py
from datetime import datetime


class ScanCreate(BaseModel):
    target: str
    scan_type: str


class FindingSchema(BaseModel):
    id: str
    description: str
    severity: str
    model_config = ConfigDict(from_attributes=True)
class ScanRequest(BaseModel):
    """Schema for scan request payload"""
    targets: List[str]
    scheduled_for: Optional[datetime] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

class ScanResult(BaseModel):
    """Schema for scan result response"""
    id: str
    targets: List[str]
    findings: List[FindingSchema]  # Update to list of Finding objects
    started_at: datetime
    completed_at: Optional[datetime] = None
    scheduled_for: Optional[datetime] = None
    status: str

    model_config = ConfigDict(arbitrary_types_allowed=True)


class ScanTaskResponse(BaseModel):
    id: str
    targets: List[str]
    findings: List[FindingSchema]  # Update to list of Finding objects
    started_at: str
    scheduled_for: Optional[datetime] = None
    status: str
    model_config = ConfigDict(from_attributes=True)
    
