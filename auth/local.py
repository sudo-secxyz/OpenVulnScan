from fastapi import APIRouter, Request, Form, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session
from passlib.hash import bcrypt
from starlette.status import HTTP_303_SEE_OTHER

from database.db_manager import SessionLocal
from auth.dependencies import get_current_user, require_admin
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

def get_current_user_template(request: Request, current_user: User = Depends(get_current_user)):
    # You can return any default value here if the user is not authenticated
    return {"request": request, "current_user": current_user}

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

@router.get("/admin/users", response_class=HTMLResponse)
def get_users(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user.is_admin():
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    users = db.query(User).all()
    return templates.TemplateResponse("user_management.html", {"request": request, "users": users, "current_user": current_user})

@router.post("/admin/users/update/{user_id}")
def update_user_by_admin(user_id: int, email: str, role: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user.is_admin():
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.email = email
    user.role = role
    db.commit()
    
    return {"msg": "User account updated successfully"}
    
@router.post("/admin/users/delete/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.id == user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own account")
    
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if not current_user.is_admin():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    
    db.delete(target_user)
    db.commit()
    
    return {"msg": "User deleted successfully"}


@router.get("/user/update", response_class=HTMLResponse)
def update_user_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return templates.TemplateResponse("update_user.html", {"request": request, "user": current_user,"current_user": current_user})


@router.post("/user/update")
def update_user(request: Request, email: str, role: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.id != request.session.get("user_id"):  # Ensure users can only update their own account
        raise HTTPException(status_code=403, detail="You can only update your own account")

    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.email = email
    user.role = role  # You can customize this further if needed
    db.commit()
    
    return {"msg": "Your account has been updated successfully"}

@router.post("/admin/create_user")
async def create_user(username: str = Form(...), email: str = Form(...), password: str = Form(...), role: str = Form(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Hash password before saving
    hashed_password = bcrypt.hash(password)  # Ensure you use a secure password hashing method.
    
    new_user = User(username=username, email=email, hashed_password=hashed_password, role=role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully"}