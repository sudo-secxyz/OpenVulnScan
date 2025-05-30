from pydantic import BaseModel

class SIEMConfigBase(BaseModel):
    enabled: bool
    host: str
    port: int
    protocol: str
    format: str

class SIEMConfigCreate(SIEMConfigBase):
    pass

class SIEMConfigUpdate(SIEMConfigBase):
    pass

class SIEMConfigOut(SIEMConfigBase):
    id: int

    class Config:
        orm_mode = True
