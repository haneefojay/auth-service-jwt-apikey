import pytest
import logging
from httpx import AsyncClient
from app.models import User
from app.auth import get_password_hash

# Set logger to DEBUG to see what's happening
logging.basicConfig(level=logging.DEBUG)

async def create_user_and_token(client: AsyncClient, email: str, role: str = "user") -> tuple[str, int]:
    # We cheat a bit here by using the signup endpoint which defaults to 'user'
    # For 'admin', we'll need to update the DB manually in the test
    # But since we can't easily access the DB session inside this helper without passing it,
    # we will rely on normal flow and update if needed, OR bypass signup and direct insert.
    pass

@pytest.mark.asyncio
async def test_access_user_route(client: AsyncClient, db):
    # Register
    await client.post("/auth/signup", json={"email": "u@test.com", "password": "UserTest123!"})
    # Login
    login_res = await client.post("/auth/login", json={"email": "u@test.com", "password": "UserTest123!"})
    token = login_res.json()["access_token"]
    
    # Access User route
    response = await client.get("/protected/user-only", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["user_email"] == "u@test.com"


