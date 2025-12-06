import pytest
import asyncio
from typing import AsyncGenerator, Generator
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool

from app.main import app
from app.database import get_db, Base
from app.auth import get_password_hash
from app.models import User
from app.config import settings

# Use the REAL database url from settings/env
# WARNING: Ideally this should be a separate test database 'auth_db_test'
TEST_DATABASE_URL = settings.DATABASE_URL

engine = create_async_engine(
    TEST_DATABASE_URL,
    poolclass=NullPool,
)

TestingSessionLocal = async_sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session")
def event_loop() -> Generator:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="function")
async def db() -> AsyncGenerator[AsyncSession, None]:
    """
    Create a fresh transaction for each test and roll it back at the end.
    This ensures tests are isolated and don't modify the actual DB permanently.
    """
    connection = await engine.connect()
    transaction = await connection.begin()
    
    session = AsyncSession(bind=connection)
    
    yield session
    
    await session.close()
    await transaction.rollback()
    await connection.close()

from httpx import AsyncClient, ASGITransport

@pytest.fixture(scope="function")
async def client(db) -> AsyncGenerator[AsyncClient, None]:
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    
    app.dependency_overrides.clear()
