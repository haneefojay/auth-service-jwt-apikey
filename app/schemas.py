from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional

# User Schemas
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: Optional[str] = "user"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

# Token Schemas
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None

# API Key Schemas
class APIKeyCreate(BaseModel):
    name: Optional[str] = None
    expires_in_days: Optional[int] = None
    scopes: Optional[str] = ""

class APIKeyResponse(BaseModel):
    id: int
    key: str
    name: Optional[str]
    user_id: int
    is_active: bool
    scopes: str
    expires_at: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True

class APIKeyList(BaseModel):
    id: int
    name: Optional[str]
    is_active: bool
    scopes: str
    expires_at: Optional[datetime]
    created_at: datetime
    revoked_at: Optional[datetime]
    
    class Config:
        from_attributes = True