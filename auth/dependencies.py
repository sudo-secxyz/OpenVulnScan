# OpenVulnScan/auth/dependencies.py
from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
from database.db_manager import get_db
from models.users import User
from models.auth import BasicUser
from fastapi import Request
from starlette.responses import RedirectResponse
from starlette.authentication import UnauthenticatedUser
from utils import config
from itsdangerous import URLSafeSerializer, BadSignature
from database.db_manager import SessionLocal


cookie_signer = URLSafeSerializer(config.SECRET_KEY, salt="auth-cookie")
COOKIE_NAME = "auth_token"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db: Session = Depends(get_db)):
    session_token = request.cookies.get("auth_token")
    if not session_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        session_data = cookie_signer.loads(session_token)
    except BadSignature:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")

    user = db.query(User).filter(User.id == session_data['id']).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def require_authentication(request: Request):
    token = request.cookies.get("auth_token")
    if not token:
        print("Token not found, redirecting to login.")
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        session_data = cookie_signer.loads(token)
        print(f"Session data: {session_data}")
        return BasicUser(**session_data)
    except Exception as e:
        print(f"Error deserializing token: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")


async def require_admin(request: Request):
    user = await require_authentication(request)
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


