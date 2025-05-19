# models/users.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from database.base import Base
from datetime import datetime
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_admin = Column(Boolean, default=False)
    auth_provider = Column(String, default="manual")  # 'google', 'github', 'wallet', 'manual'
    wallet_address = Column(String, unique=True, nullable=True)
    role = Column(String, default="user")  # "admin", "user", "readonly"


    def is_admin(self):
        if isinstance(self.is_admin, bool):
            return self.is_admin
        return self.role == "admin"
    
    def is_readonly(self):
        return self.role == "readonly"