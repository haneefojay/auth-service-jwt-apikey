from pydantic import BaseModel, EmailStr
from uuid import UUID
from datetime import datetime
from typing import Optional

# User Schemas
class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: UUID
    email: str

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


# API Key Schemas
class APIKeyCreate(BaseModel):
    name: Optional[str] = None
    expires_in_days: Optional[int] = None


class APIKeyResponse(BaseModel):
    id: UUID
    key: str
    name: Optional[str]
    user_id: UUID
    is_active: bool
    expires_at: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True

class APIKeyList(BaseModel):
    id: UUID
    name: Optional[str]
    is_active: bool
    expires_at: Optional[datetime]
    created_at: datetime
    revoked_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class APIKeyRevoke(BaseModel):
    id: UUID
    name: Optional[str]
    is_active: bool = False
    expires_at: Optional[datetime]
    created_at: datetime
    revoked_at: Optional[datetime]
    
    class Config:
        from_attributes = True