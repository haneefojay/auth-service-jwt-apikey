from datetime import datetime, timedelta
from typing import Optional, Union
from jose import JWTError, jwt
# from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from .config import settings
from .database import get_db
from . import models, schemas
from .utils import hash_api_key

import bcrypt
import secrets

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Define two separate security schemes matching the OpenAPI schema
jwt_bearer = HTTPBearer(scheme_name="JWTBearer")
api_key_bearer = HTTPBearer(scheme_name="APIKeyBearer")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # return pwd_context.verify(plain_password, hashed_password)
    # Ensure bytes for bcrypt
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    if isinstance(plain_password, str):
        plain_password = plain_password.encode('utf-8')
    
    return bcrypt.checkpw(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    # return pwd_context.hash(password)
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

from uuid import UUID

def create_refresh_token(user_id: UUID) -> str:
    timestamp = datetime.utcnow().isoformat()
    return f"rt_{secrets.token_urlsafe(32)}_{timestamp}"

async def authenticate_user(db: AsyncSession, email: str, password: str):
    result = await db.execute(select(models.User).filter(models.User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

async def get_current_user_from_token(
    credentials: HTTPAuthorizationCredentials = Security(jwt_bearer),
    db: AsyncSession = Depends(get_db)
) -> models.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token = credentials.credentials
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    result = await db.execute(select(models.User).filter(models.User.email == email))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    
    return user

async def get_current_user_from_api_key(
    credentials: HTTPAuthorizationCredentials = Security(api_key_bearer),
    db: AsyncSession = Depends(get_db)
) -> models.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    api_key_value = credentials.credentials
    
    # Check if it's an API key (starts with 'sk_' prefix)
    if not api_key_value.startswith('sk_'):
        raise credentials_exception
    
    result = await db.execute(
        select(models.APIKey).filter(
            models.APIKey.key == hash_api_key(api_key_value),
            models.APIKey.is_active == True
        )
    )
    key_record = result.scalar_one_or_none()
    
    if not key_record:
        raise credentials_exception
    
    # Check if expired
    if key_record.expires_at and key_record.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired"
        )
    
    result = await db.execute(select(models.User).filter(models.User.id == key_record.user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise credentials_exception
    
    return user

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(jwt_bearer),
    db: AsyncSession = Depends(get_db)
) -> tuple[models.User, str]:
    """
    Returns (user, auth_type)
    auth_type is 'jwt' or 'api_key'
    
    Accepts either:
    - JWT Bearer Token (from /auth/login)
    - API Key (starts with sk_, from /keys/create)
    """
    token = credentials.credentials
    
    # Try API key first (if starts with sk_)
    if token.startswith('sk_'):
        try:
            user = await get_current_user_from_api_key(credentials, db)
            return user, "api_key"
        except HTTPException:
            raise
    
    # Try JWT token
    try:
        user = await get_current_user_from_token(credentials, db)
        return user, "jwt"
    except HTTPException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials. Provide either a valid JWT token or API key."
        )



def require_service_access(current_user_data: tuple = Depends(get_current_user)):
    user, auth_type = current_user_data
    if auth_type != "api_key":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Service access required (API Key)"
        )
    return user