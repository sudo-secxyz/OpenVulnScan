#auth/local.py
from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER
from passlib.hash import bcrypt
from itsdangerous import URLSafeSerializer, BadSignature
from fastapi.templating import Jinja2Templates
from auth.dependencies import cookie_signer, get_current_user


from database.db_manager import SessionLocal
from models.users import User
from models.auth import BasicUser
from config import TEMPLATES_DIR

router = APIRouter()
templates = Jinja2Templates(directory=TEMPLATES_DIR)
serializer = cookie_signer

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Route to show the login page
@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# Login functionality with session token creation
@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # Fetch user from the database
    user = db.query(User).filter(User.email == email).first()

    # Validate the user credentials
    if not user or not bcrypt.verify(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid email or password"
        })

    # Prepare session data
    session_data = {"id": user.id, "email": user.email, "role": user.role}

    # Serialize the session data
    token = serializer.dumps(session_data)

    # Prepare the response with a redirect and set the auth_token in a cookie
    response = RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    response.set_cookie("auth_token", token, httponly=True, max_age=60*60*24*14)  # 14 days max age

    return response

# Route for user registration
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
    new_user = User(email=email, hashed_password=hashed_pw, role="user")
    db.add(new_user)
    db.commit()
    return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)

# Logout functionality and clearing the session token
@router.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    response.delete_cookie("session_token")
    return response

# Admin routes protected by authentication
@router.get("/admin/users", response_class=HTMLResponse)
def admin_user_list(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    users = db.query(User).all()
    return templates.TemplateResponse("user_management.html", {"request": request, "users": users, "current_user": user})

@router.post("/admin/users/update/{user_id}")
def admin_user_update(user_id: int, email: str, role: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_user.email = email
    db_user.role = role
    db.commit()
    return {"msg": "User account updated successfully"}

@router.post("/admin/users/delete/{user_id}")
def admin_user_delete(user_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(db_user)
    db.commit()
    return {"msg": "User deleted successfully"}

# User update route, with authentication
@router.get("/user/update", response_class=HTMLResponse)
def user_update_page(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return templates.TemplateResponse("update_user.html", {"request": request, "user": user, "current_user": user})

@router.post("/user/update")
def user_update(request: Request, email: str, role: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # Ensure user can only update their own account
    if user.id != user.id:
        raise HTTPException(status_code=403, detail="You can only update your own account")

    db_user = db.query(User).filter(User.id == user.id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_user.email = email
    db_user.role = role
    db.commit()
    return {"msg": "Your account has been updated successfully"}

# Admin user creation route
@router.post("/admin/create_user")
async def admin_create_user(username: str = Form(...), email: str = Form(...), password: str = Form(...), role: str = Form(...), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    new_user = User(username=username, email=email, hashed_password=bcrypt.hash(password), role=role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}
