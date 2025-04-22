from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session
from passlib.hash import bcrypt
from starlette.status import HTTP_303_SEE_OTHER

from database.db_manager import SessionLocal
from models.users import User
from config import TEMPLATES_DIR
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory=TEMPLATES_DIR)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not bcrypt.verify(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid email or password"
        })
    request.session["user"] = {
        "id": user.id,
        "email": user.email,
        "is_admin": user.is_admin
    }
    return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)

@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "User already exists"
        })
    hashed_pw = bcrypt.hash(password)
    user = User(email=email, hashed_password=hashed_pw, is_admin=False)
    db.add(user)
    db.commit()
    return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)

@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
