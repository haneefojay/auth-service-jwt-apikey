import hashlib
import secrets
import re
from typing import Optional

def validate_password(password: str) -> Optional[str]:
    """
    Validate password against security policy.
    
    Returns None if valid, or an error message string if invalid.
    
    Requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit (0-9)
    - At least one special character
    """
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number (0-9)")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;\'`~]', password):
        errors.append("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>_-+=[]\\\/;'`~)")
    
    if errors:
        return "; ".join(errors)
    
    return None

def generate_api_key_str() -> str:
    """Generate a secure, random API key string."""
    return f"sk_{secrets.token_urlsafe(32)}"

def hash_api_key(api_key: str) -> str:
    """Hash the API key using SHA256 before storing."""
    return hashlib.sha256(api_key.encode()).hexdigest()

def verify_api_key(plain_api_key: str, hashed_api_key: str) -> bool:
    """Verify if the plain API key matches the stored hash."""
    return hash_api_key(plain_api_key) == hashed_api_key
