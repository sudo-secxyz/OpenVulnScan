from fastapi import APIRouter, Depends, HTTPException, Form, Request
from sqlalchemy.orm import Session
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.exc import IntegrityError

from database.db_manager import get_db
from schemas.tag import TagCreate, TagResponse
from services.tag_service import create_tag, get_tags, assign_tag_to_asset, remove_tag_from_asset
from auth.dependencies import get_current_user
from models.tag import Tag

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/tags", response_model=list[TagResponse])
def list_tags_api(db: Session = Depends(get_db)):
    """
    API endpoint: List all tags (returns JSON).
    """
    return db.query(Tag).all()

@router.post("/tags/create")
def create_tag_form(
    request: Request,  # <-- add this!
    name: str = Form(...),
    description: str = Form(None),
    db: Session = Depends(get_db)
):
    try:
        create_tag(db, name, description)
        return RedirectResponse(url="/tags", status_code=303)
    except IntegrityError:
        db.rollback()
        return templates.TemplateResponse(
            "tags.html",
            {
                "request": request,  # <-- pass it here!
                "tags": db.query(Tag).all(),
                "error": f"Tag '{name}' already exists."
            },
            status_code=400
        )

@router.get("/tags", response_model=list[TagResponse])
def list_tags_route(request, db: Session = Depends(get_db), user=Depends(get_current_user)):
    tags = db.query(Tag).all()
    return templates.TemplateResponse("tags.html", {"request": request, "tags": tags})

@router.post("/assets/{asset_id}/tags/{tag_id}")
def assign_tag_route(asset_id: int, tag_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    # Add permission check here if needed
    asset = assign_tag_to_asset(db, asset_id, tag_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset or tag not found")
    return {"message": "Tag assigned"}

@router.delete("/assets/{asset_id}/tags/{tag_id}")
def remove_tag_route(asset_id: int, tag_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    # Add permission check here if needed
    asset = remove_tag_from_asset(db, asset_id, tag_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset or tag not found")
    return {"message": "Tag removed"}

@router.post("/tags/{tag_id}/delete")
def delete_tag(tag_id: int, db: Session = Depends(get_db)):
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if tag:
        db.delete(tag)
        db.commit()
    return RedirectResponse(url="/tags", status_code=303)

@router.post("/tags", response_model=TagResponse)
def create_tag_route(tag: TagCreate, db: Session = Depends(get_db)):
    return create_tag(db, tag.name, tag.description)