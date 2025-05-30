from sqlalchemy.orm import Session
from models.siem_config import SIEMConfig
from schemas.siem_config import SIEMConfigCreate, SIEMConfigUpdate

def get_config(db: Session):
    return db.query(SIEMConfig).first()

def create_config(db: Session, config: SIEMConfigCreate):
    db_config = SIEMConfig(**config.dict())
    db.add(db_config)
    db.commit()
    db.refresh(db_config)
    return db_config

def update_config(db: Session, config: SIEMConfigUpdate):
    db_config = get_config(db)
    if db_config:
        for key, value in config.dict().items():
            setattr(db_config, key, value)
        db.commit()
        db.refresh(db_config)
    return db_config
