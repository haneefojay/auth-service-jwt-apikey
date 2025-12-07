from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta
from typing import List
from typing import List
from uuid import UUID
import secrets
from slowapi import Limiter
from slowapi.util import get_remote_address
from .. import models, schemas, auth
from ..database import get_db
from ..utils import hash_api_key
from ..config import settings

router = APIRouter(prefix="/keys", tags=["API Keys"])
limiter = Limiter(key_func=get_remote_address, enabled=not settings.TESTING)

def generate_api_key() -> str:
    """Generate a secure API key with sk_ prefix"""
    return f"sk_{secrets.token_urlsafe(32)}"

@router.post("/create", response_model=schemas.APIKeyResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")
async def create_api_key(
    request: Request,
    key_data: schemas.APIKeyCreate,
    current_user_data: tuple = Depends(auth.get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new API key for the authenticated user
    """
    user, auth_type = current_user_data
    
    # Generate unique API key
    api_key = generate_api_key()
    
    # Calculate expiration date
    max_expiration_days = 90
    if key_data.expires_in_days and key_data.expires_in_days > max_expiration_days:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Expiration cannot exceed {max_expiration_days} days"
        )
    
    expires_in = key_data.expires_in_days if key_data.expires_in_days else max_expiration_days
    expires_at = datetime.utcnow() + timedelta(days=expires_in)
    
    # Create API key record (store hash)
    new_key = models.APIKey(
        key=hash_api_key(api_key),
        name=key_data.name,
        user_id=user.id,

        expires_at=expires_at
    )
    
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)
    
    # Return raw key to user (this is the only time they see it)
    # We create a response object manually or overlay the raw key onto the model for response
    # Because refresh(new_key) loads the hashed key back.
    
    # We cheat slightly on the response model for this one instance to show the raw key
    # create a Pydantic object manually
    return schemas.APIKeyResponse(
        id=new_key.id,
        key=api_key, # Raw key
        name=new_key.name,
        user_id=new_key.user_id,
        is_active=new_key.is_active,
        expires_at=new_key.expires_at,
        created_at=new_key.created_at
    )

@router.get("/list", response_model=List[schemas.APIKeyList])
@limiter.limit("30/minute")
async def list_api_keys(
    request: Request,
    current_user_data: tuple = Depends(auth.get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all API keys for the authenticated user (excludes actual key values for security)
    """
    user, auth_type = current_user_data
    
    result = await db.execute(select(models.APIKey).filter(models.APIKey.user_id == user.id))
    keys = result.scalars().all()
    
    return keys

@router.delete("/revoke/{key_id}", response_model=schemas.APIKeyRevoke, status_code=status.HTTP_200_OK)
@limiter.limit("20/hour")
async def revoke_api_key(
    request: Request,
    key_id: UUID,
    current_user_data: tuple = Depends(auth.get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Revoke (deactivate) an API key
    """
    user, auth_type = current_user_data
    
    # Find the key
    result = await db.execute(
        select(models.APIKey).filter(
            models.APIKey.id == key_id,
            models.APIKey.user_id == user.id
        )
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    # Revoke the key
    api_key.is_active = False
    api_key.revoked_at = datetime.utcnow()
    
    await db.commit()
    await db.refresh(api_key)
    
    return api_key
