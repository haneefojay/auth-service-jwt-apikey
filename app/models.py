from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Uuid
import uuid
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Uuid, primary_key=True, default=uuid.uuid4, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    api_keys = relationship("APIKey", back_populates="user")
    refresh_tokens = relationship("RefreshToken", back_populates="user")

class APIKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(Uuid, primary_key=True, default=uuid.uuid4, index=True)
    key = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=True)
    user_id = Column(Uuid, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True)
    
    user = relationship("User", back_populates="api_keys")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    
    id = Column(Uuid, primary_key=True, default=uuid.uuid4, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Uuid, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True)
    
    user = relationship("User", back_populates="refresh_tokens")