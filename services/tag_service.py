from sqlalchemy.orm import Session
from models.tag import Tag
from models.asset import Asset

def create_tag(db: Session, name: str, description: str = None):
    tag = Tag(name=name, description=description)
    db.add(tag)
    db.commit()
    db.refresh(tag)
    return tag

def get_tags(db: Session):
    return db.query(Tag).all()

def assign_tag_to_asset(db: Session, asset_id: int, tag_id: int):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if asset and tag and tag not in asset.tags:
        asset.tags.append(tag)
        db.commit()
    return asset

def remove_tag_from_asset(db: Session, asset_id: int, tag_id: int):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if asset and tag and tag in asset.tags:
        asset.tags.remove(tag)
        db.commit()
    return asset