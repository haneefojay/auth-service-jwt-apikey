import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.models import User, RefreshToken

@pytest.mark.asyncio
async def test_signup(client: AsyncClient, db):
    response = await client.post("/auth/signup", json={
        "email": "test@example.com", 
        "password": "password123"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert "role" in data
    assert data["role"] == "user" # Default role

    # Check DB
    result = await db.execute(select(User).filter(User.email == "test@example.com"))
    user = result.scalar_one_or_none()
    assert user is not None
    assert user.role == "user"

@pytest.mark.asyncio
async def test_login(client: AsyncClient):
    # Register first
    await client.post("/auth/signup", json={
        "email": "test@example.com", 
        "password": "password123"
    })

    # Login
    response = await client.post("/auth/login", json={
        "email": "test@example.com", 
        "password": "password123"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

@pytest.mark.asyncio
async def test_refresh_token(client: AsyncClient):
    # Setup user and login
    await client.post("/auth/signup", json={
        "email": "refresh@example.com", 
        "password": "password123"
    })
    login_res = await client.post("/auth/login", json={
        "email": "refresh@example.com", 
        "password": "password123"
    })
    refresh_token = login_res.json()["refresh_token"]

    # Refresh
    response = await client.post(f"/auth/refresh?refresh_token={refresh_token}")
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["refresh_token"] != refresh_token # Should rotate
