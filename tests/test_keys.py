import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_api_key_access(client: AsyncClient):
    # Register & Login
    await client.post("/auth/signup", json={"email": "k@test.com", "password": "TestKey123!"})
    login_res = await client.post("/auth/login", json={"email": "k@test.com", "password": "TestKey123!"})
    token = login_res.json()["access_token"]
    
    # Create Key (no scopes)
    key_res = await client.post("/keys/create", 
        json={"name": "Service Key"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert key_res.status_code == 201
    api_key = key_res.json()["key"]
    
    # Access Service Route (requires API Key)
    res = await client.get("/protected/service-only", headers={"Authorization": f"Bearer {api_key}"})
    assert res.status_code == 200
    assert res.json()["auth_type"] == "api_key"

@pytest.mark.asyncio
async def test_jwt_cannot_access_service_route(client: AsyncClient):
    # Register & Login
    await client.post("/auth/signup", json={"email": "k2@test.com", "password": "TestKey456!"})
    login_res = await client.post("/auth/login", json={"email": "k2@test.com", "password": "TestKey456!"})
    token = login_res.json()["access_token"]
    
    # Try Accessing Service Only Route with JWT
    res = await client.get("/protected/service-only", headers={"Authorization": f"Bearer {token}"})
    # Should be 403 Forbidden because route requires require_service_access (API Key only)
    assert res.status_code == 403

@pytest.mark.asyncio
async def test_api_key_expiration_policy(client: AsyncClient):
    # Register & Login
    await client.post("/auth/signup", json={"email": "k_exp@test.com", "password": "ExpireTest789!"})
    login_res = await client.post("/auth/login", json={"email": "k_exp@test.com", "password": "ExpireTest789!"})
    token = login_res.json()["access_token"]
    
    # 1. Test Default Expiration (should be 90 days)
    res_default = await client.post("/keys/create", 
        json={"name": "Default Key"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_default.status_code == 201
    assert res_default.json()["expires_at"] is not None

    # 2. Test Exceeding Max Expiration (e.g., 91 days)
    res_fail = await client.post("/keys/create", 
        json={"name": "Long Key", "expires_in_days": 91},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_fail.status_code == 400
    assert "cannot exceed 90 days" in res_fail.json()["detail"]

    # 3. Test Valid Custom Expiration (e.g., 30 days)
    res_custom = await client.post("/keys/create", 
        json={"name": "Short Key", "expires_in_days": 30},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_custom.status_code == 201
