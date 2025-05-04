from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class FindingSchema(BaseModel):
    id: int
    scan_id: str
    ip_address: str
    hostname: Optional[str] = None
    raw_data: Optional[str] = None
    created_at: datetime

    class Config:
        orm_mode = True
