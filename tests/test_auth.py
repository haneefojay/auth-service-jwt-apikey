import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.models import User, RefreshToken

@pytest.mark.asyncio
async def test_signup(client: AsyncClient, db):
    response = await client.post("/auth/signup", json={
        "email": "test@example.com", 
        "password": "SecurePass123!"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    # Check DB
    result = await db.execute(select(User).filter(User.email == "test@example.com"))
    user = result.scalar_one_or_none()
    assert user is not None

@pytest.mark.asyncio
async def test_signup_password_too_short(client: AsyncClient):
    response = await client.post("/auth/signup", json={
        "email": "test@example.com", 
        "password": "Short1!"
    })
    assert response.status_code == 400
    assert "at least 8 characters" in response.json()["detail"]

@pytest.mark.asyncio
async def test_signup_password_no_uppercase(client: AsyncClient):
    response = await client.post("/auth/signup", json={
        "email": "test@example.com", 
        "password": "lowercase123!"
    })
    assert response.status_code == 400
    assert "uppercase letter" in response.json()["detail"]

@pytest.mark.asyncio
async def test_signup_password_no_lowercase(client: AsyncClient):
    response = await client.post("/auth/signup", json={
        "email": "test@example.com", 
        "password": "UPPERCASE123!"
    })
    assert response.status_code == 400
    assert "lowercase letter" in response.json()["detail"]

@pytest.mark.asyncio
async def test_signup_password_no_number(client: AsyncClient):
    response = await client.post("/auth/signup", json={
        "email": "test@example.com", 
        "password": "NoNumbers!"
    })
    assert response.status_code == 400
    assert "number" in response.json()["detail"]

@pytest.mark.asyncio
async def test_signup_password_no_special_char(client: AsyncClient):
    response = await client.post("/auth/signup", json={
        "email": "test@example.com", 
        "password": "NoSpecial123"
    })
    assert response.status_code == 400
    assert "special character" in response.json()["detail"]

@pytest.mark.asyncio
async def test_signup_password_multiple_violations(client: AsyncClient):
    response = await client.post("/auth/signup", json={
        "email": "test@example.com", 
        "password": "weak"
    })
    assert response.status_code == 400
    detail = response.json()["detail"]
    # Should contain multiple error messages
    assert "8 characters" in detail
    assert "uppercase" in detail
    assert "number" in detail
    assert "special character" in detail

@pytest.mark.asyncio
async def test_login(client: AsyncClient):
    # Register first
    await client.post("/auth/signup", json={
        "email": "test@example.com", 
        "password": "SecurePass123!"
    })

    # Login
    response = await client.post("/auth/login", json={
        "email": "test@example.com", 
        "password": "SecurePass123!"
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
        "password": "RefreshPass123!"
    })
    login_res = await client.post("/auth/login", json={
        "email": "refresh@example.com", 
        "password": "RefreshPass123!"
    })
    refresh_token = login_res.json()["refresh_token"]

    # Refresh
    response = await client.post(f"/auth/refresh?refresh_token={refresh_token}")
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["refresh_token"] != refresh_token # Should rotate
