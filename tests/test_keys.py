import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_api_key_scopes(client: AsyncClient):
    # Register & Login
    await client.post("/auth/signup", json={"email": "k@test.com", "password": "pwm"})
    login_res = await client.post("/auth/login", json={"email": "k@test.com", "password": "pwm"})
    token = login_res.json()["access_token"]
    
    # Create Key with "read" scope
    key_res = await client.post("/keys/create", 
        json={"name": "Read Key", "scopes": "read"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert key_res.status_code == 201
    api_key = key_res.json()["key"]
    
    # Access Service Route (requires "read")
    res = await client.get("/protected/service-only", headers={"Authorization": f"Bearer {api_key}"})
    assert res.status_code == 200
    assert "read" in res.json()["scopes"]

@pytest.mark.asyncio
async def test_api_key_missing_scope(client: AsyncClient):
    # Register & Login
    await client.post("/auth/signup", json={"email": "k2@test.com", "password": "pwm"})
    login_res = await client.post("/auth/login", json={"email": "k2@test.com", "password": "pwm"})
    token = login_res.json()["access_token"]
    
    # Create Key with "write" scope (missing "read")
    key_res = await client.post("/keys/create", 
        json={"name": "Write Key", "scopes": "write"},
        headers={"Authorization": f"Bearer {token}"}
    )
    api_key = key_res.json()["key"]
    
    # Access Service Route (requires "read")
    res = await client.get("/protected/service-only", headers={"Authorization": f"Bearer {api_key}"})
    assert res.status_code == 403
