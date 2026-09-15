import os

import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)

from httpx import ASGITransport, AsyncClient

from app.database import get_session
from app.main import app

from app.models import Base


@pytest_asyncio.fixture
async def test_session():
    database_url = os.getenv("TEST_DATABASE_URL")

    if not database_url:
        raise RuntimeError(
            "TEST_DATABASE_URL must be configured."
        )

    if not database_url.endswith("/tracepilot_test"):
        raise RuntimeError(
            "Tests must use the tracepilot_test database."
        )

    engine = create_async_engine(database_url)

    async with engine.begin() as connection:
        await connection.run_sync(
            Base.metadata.drop_all
        )
        await connection.run_sync(
            Base.metadata.create_all
        )

    session_factory = async_sessionmaker(
        engine,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        yield session

    async with engine.begin() as connection:
        await connection.run_sync(
            Base.metadata.drop_all
        )

    await engine.dispose()
    
@pytest_asyncio.fixture
async def client(test_session):
    async def override_get_session():
        yield test_session

    app.dependency_overrides[get_session] = (
        override_get_session
    )

    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as test_client:
        yield test_client

    app.dependency_overrides.clear()
