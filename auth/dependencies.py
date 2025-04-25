# OpenVulnScan/auth/dependencies.py
from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
from database.db_manager import get_db
from models.users import User
from fastapi import Request
from starlette.responses import RedirectResponse
from starlette.authentication import UnauthenticatedUser

def require_authentication(request: Request, db: Session = Depends(get_db)) -> User:
    user_data = request.session.get("user")
    if not user_data:
        raise HTTPException(status_code=401, detail="Authentication required")

    user_email = user_data["email"]  # Assuming 'email' is in the session data
    user = db.query(User).filter_by(email=user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")

    return user



def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_data = request.session.get("user")
    if not user_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    user_id = user_data["id"]  # Directly use the 'id' from session
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    return user

