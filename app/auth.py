from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
# from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from .config import settings
from .database import get_db
from . import models, schemas

import bcrypt
import secrets

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

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

def create_refresh_token(user_id: int) -> str:
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
    credentials: HTTPAuthorizationCredentials = Security(security),
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
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: AsyncSession = Depends(get_db)
) -> tuple[models.User, list[str]]:
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
            models.APIKey.key == api_key_value,
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
    
    scopes = key_record.scopes.split(',') if key_record.scopes else []
    return user, scopes

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: AsyncSession = Depends(get_db)
) -> tuple[models.User, str, list[str]]:
    """
    Returns (user, auth_type, scopes)
    auth_type is 'jwt' or 'api_key'
    scopes is list of permission strings (empty for JWT currently implies full access or handled differently)
    """
    token = credentials.credentials
    
    # Try API key first (if starts with sk_)
    if token.startswith('sk_'):
        try:
            user, scopes = await get_current_user_from_api_key(credentials, db)
            return user, "api_key", scopes
        except HTTPException:
            raise
    
    # Try JWT token
    try:
        user = await get_current_user_from_token(credentials, db)
        # JWT users implicitly have all scopes for now, or you could add scopes to JWT
        return user, "jwt", ["*"] 
    except HTTPException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

def check_admin(current_user_data: tuple = Depends(get_current_user)):
    user, auth_type, scopes = current_user_data
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return user

def require_scope(scope: str):
    def scope_checker(current_user_data: tuple = Depends(get_current_user)):
        user, auth_type, scopes = current_user_data
        if "*" in scopes:
            return user
        if scope not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope: {scope}"
            )
        return user
    return scope_checker