from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta
from slowapi import Limiter
from slowapi.util import get_remote_address
from .. import models, schemas, auth
from ..database import get_db
from ..config import settings
from ..utils import validate_password

router = APIRouter(prefix="/auth", tags=["Authentication"])
limiter = Limiter(key_func=get_remote_address, enabled=not settings.TESTING)

@router.post("/signup", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/hour")
async def signup(request: Request, user: schemas.UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Register a new user
    """
    # Validate password policy
    password_error = validate_password(user.password)
    if password_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=password_error
        )
    
    # Check if user already exists
    result = await db.execute(select(models.User).filter(models.User.email == user.email))
    db_user = result.scalar_one_or_none()
    
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user
    hashed_password = auth.get_password_hash(user.password)
    new_user = models.User(
        email=user.email,
        hashed_password=hashed_password
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    return new_user

@router.post("/login", response_model=schemas.Token)
@limiter.limit("10/minute")
async def login(request: Request, user_credentials: schemas.UserLogin, db: AsyncSession = Depends(get_db)):
    """
    Login and get JWT token + Refresh Token
    """
    user = await auth.authenticate_user(db, user_credentials.email, user_credentials.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Access Token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    # Refresh Token
    refresh_token = auth.create_refresh_token(user.id)
    new_refresh_token = models.RefreshToken(
        token=refresh_token,
        user_id=user.id,
        expires_at=datetime.utcnow() + timedelta(days=7) # 7 days validity
    )
    db.add(new_refresh_token)
    await db.commit()
    
    return {
        "access_token": access_token, 
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.post("/refresh", response_model=schemas.Token)
@limiter.limit("20/hour")
async def refresh_token(
    request: Request,
    refresh_token: str, 
    db: AsyncSession = Depends(get_db)
):
    """
    Get new access token using refresh token
    """
    # Find active refresh token
    result = await db.execute(
        select(models.RefreshToken).filter(
            models.RefreshToken.token == refresh_token,
            models.RefreshToken.revoked_at == None,
            models.RefreshToken.expires_at > datetime.utcnow()
        )
    )
    token_record = result.scalar_one_or_none()
    
    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
        
    # Get user
    result = await db.execute(select(models.User).filter(models.User.id == token_record.user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Rotate refresh token (optional security best practice: revoke old, issue new)
    token_record.revoked_at = datetime.utcnow()
    
    new_refresh_token_val = auth.create_refresh_token(user.id)
    new_refresh_token = models.RefreshToken(
        token=new_refresh_token_val,
        user_id=user.id,
        expires_at=datetime.utcnow() + timedelta(days=7)
    )
    db.add(new_refresh_token)
    
    # Store user data before commit expires the object
    user_email = user.email

    
    await db.commit()
    
    # New Access Token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user_email}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token, 
        "refresh_token": new_refresh_token_val,
        "token_type": "bearer"
    }

@router.get("/me", response_model=schemas.UserResponse)
async def get_current_user_info(
    current_user_data: tuple = Depends(auth.get_current_user)
):
    """
    Get current user information (works with both JWT and API key)
    """
    user, auth_type = current_user_data
    return user