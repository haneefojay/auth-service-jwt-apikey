from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta
from .. import models, schemas, auth
from ..database import get_db
from ..config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/signup", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
async def signup(user: schemas.UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Register a new user
    """
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
    # Simple default role assignment logic
    role = user.role if user.role in ["admin", "user"] else "user"
    
    new_user = models.User(
        email=user.email,
        hashed_password=hashed_password,
        role=role
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    return new_user

@router.post("/login", response_model=schemas.Token)
async def login(user_credentials: schemas.UserLogin, db: AsyncSession = Depends(get_db)):
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
        data={"sub": user.email, "role": user.role}, expires_delta=access_token_expires
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
async def refresh_token(
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
    user_role = user.role
    
    await db.commit()
    
    # New Access Token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user_email, "role": user_role}, expires_delta=access_token_expires
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
    user, auth_type, scopes = current_user_data
    return user