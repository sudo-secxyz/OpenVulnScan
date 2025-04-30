# models/schemas.py

from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from datetime import datetime

class ScanRequest(BaseModel):
    """Schema for scan request payload"""
    targets: List[str]
    scheduled_for: Optional[datetime] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

class ScanResult(BaseModel):
    """Schema for scan result response"""
    id: str
    targets: List[str]
    findings: List[str]
    started_at: datetime
    completed_at: Optional[datetime] = None
    scheduled_for: Optional[datetime] = None
    status: str

    model_config = ConfigDict(arbitrary_types_allowed=True)

class ScanTaskResponse(BaseModel):
    id: str
    targets: List[str]
    findings: List[dict]
    started_at: str
    scheduled_for: Optional[datetime] = None
    status: str

    
