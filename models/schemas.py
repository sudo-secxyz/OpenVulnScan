# models/schemas.py
from pydantic import BaseModel
from typing import List, Optional
import datetime

class ScanRequest(BaseModel):
    """Schema for scan request payload"""
    targets: List[str]

class ScanResult(BaseModel):
    """Schema for scan result response"""
    id: str
    targets: List[str]
    findings: List[str]
    started_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None