# OpenVulnScan/auth/dependencies.py

from fastapi import Request
from starlette.responses import RedirectResponse

def require_authentication(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return user

from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
from database.db_manager import get_db
from models.users import User

def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    return user
