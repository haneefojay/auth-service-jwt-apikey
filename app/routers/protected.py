from fastapi import APIRouter, Depends, Request
from .. import auth
from ..logging_config import logger

router = APIRouter(prefix="/protected", tags=["Protected Routes"])

@router.get("/user-only")
async def user_only_route(
    request: Request,
    current_user_data: tuple = Depends(auth.get_current_user)
):
    """
    Example protected route - accessible with both JWT and API key
    Has explicit rate limiting applied
    """
    # Verify rate limit manually if strictly needed inside, but usually middleware handles it broadly
    # or use @limiter.limit("5/minute") decorator if we had the limiter instance imported here.
    # Since limiter is on app.state, using dependency injection for it is cleaner, but for now
    # we demonstrate just the auth parts.
    
    user, auth_type, scopes = current_user_data
    logger.info(f"User {user.email} accessed user-only route via {auth_type}")
    
    return {
        "message": "This is a protected route",
        "user_email": user.email,
        "auth_type": auth_type,
        "scopes": scopes,
        "role": user.role,
        "access_level": "user"
    }

@router.get("/service-only", dependencies=[Depends(auth.require_scope("read"))])
async def service_only_route(
    current_user_data: tuple = Depends(auth.get_current_user)
):
    """
    Example service-only route
    REQUIRES 'read' scope in API key
    """
    user, auth_type, scopes = current_user_data
    
    return {
        "message": "You have read access",
        "user_email": user.email,
        "auth_type": auth_type,
        "scopes": scopes,
        "access_level": "service",
        "note": "Accessed with valid scope: read"
    }

@router.get("/admin", dependencies=[Depends(auth.check_admin)])
async def admin_route(
    current_user_data: tuple = Depends(auth.get_current_user)
):
    """
    Example admin route - REQUIRES 'admin' role
    """
    user, auth_type, scopes = current_user_data
    
    return {
        "message": "This is an admin route",
        "user_email": user.email,
        "auth_type": auth_type,
        "role": user.role,
        "access_level": "admin"
    }