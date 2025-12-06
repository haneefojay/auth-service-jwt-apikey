from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta
from typing import List
import secrets
from .. import models, schemas, auth
from ..database import get_db

router = APIRouter(prefix="/keys", tags=["API Keys"])

def generate_api_key() -> str:
    """Generate a secure API key with sk_ prefix"""
    return f"sk_{secrets.token_urlsafe(32)}"

@router.post("/create", response_model=schemas.APIKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    key_data: schemas.APIKeyCreate,
    current_user_data: tuple = Depends(auth.get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new API key for the authenticated user
    """
    user, auth_type, scopes = current_user_data
    
    # Generate unique API key
    api_key = generate_api_key()
    
    # Calculate expiration date if provided
    expires_at = None
    if key_data.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=key_data.expires_in_days)
    
    # Create API key record
    new_key = models.APIKey(
        key=api_key,
        name=key_data.name,
        user_id=user.id,
        scopes=key_data.scopes or "", # Handle scopes
        expires_at=expires_at
    )
    
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)
    
    return new_key

@router.get("/list", response_model=List[schemas.APIKeyList])
async def list_api_keys(
    current_user_data: tuple = Depends(auth.get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all API keys for the authenticated user (excludes actual key values for security)
    """
    user, auth_type, scopes = current_user_data
    
    result = await db.execute(select(models.APIKey).filter(models.APIKey.user_id == user.id))
    keys = result.scalars().all()
    
    return keys

@router.delete("/revoke/{key_id}", status_code=status.HTTP_200_OK)
async def revoke_api_key(
    key_id: int,
    current_user_data: tuple = Depends(auth.get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Revoke (deactivate) an API key
    """
    user, auth_type, scopes = current_user_data
    
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
    
    return {"message": "API key revoked successfully", "key_id": key_id}

@router.delete("/delete/{key_id}", status_code=status.HTTP_200_OK)
async def delete_api_key(
    key_id: int,
    current_user_data: tuple = Depends(auth.get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Permanently delete an API key
    """
    user, auth_type, scopes = current_user_data
    
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
    
    # Delete the key
    await db.delete(api_key)
    await db.commit()
    
    return {"message": "API key deleted successfully", "key_id": key_id}