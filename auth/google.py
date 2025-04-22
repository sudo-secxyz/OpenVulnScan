from fastapi import APIRouter, Request, Depends

from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from sqlalchemy.orm import Session
from database.db_manager import get_db
from models.users import User
import os

router = APIRouter()

config = Config('.env')
oauth = OAuth(config)
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

@router.get("/auth")
async def google_auth():
    return {"msg": "Google auth route"}

@router.get('/login/google')
async def login_via_google(request: Request):
    redirect_uri = request.url_for('auth_google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get('/auth/google/callback')
async def auth_google_callback(request: Request, db: Session = Depends(get_db)):
    token = await oauth.google.authorize_access_token(request)
    user_info = await oauth.google.parse_id_token(request, token)

    email = user_info['email']
    username = user_info.get('name', email)

    # Check if user exists
    user = db.query(User).filter_by(email=email).first()
    if not user:
        user = User(email=email, username=username, auth_provider='google')
        db.add(user)
        db.commit()
        db.refresh(user)

    # You can return a session token here (JWT) or a success message
    return {"message": f"Welcome, {username}", "user_id": user.id}
