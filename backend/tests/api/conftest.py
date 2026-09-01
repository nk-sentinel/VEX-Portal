"""Fixtures for the API test suite."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import get_session, make_engine, session_factory
from app.main import create_app
from app.repos.models import Base


@pytest.fixture
def client() -> Iterator[TestClient]:
    """A `TestClient` bound to a fresh app instance, running the app's lifespan.

    Entered as a context manager so startup/shutdown handlers actually run —
    a bare `TestClient(create_app())` never fires them, which would leave the
    lifespan's engine-disposal path untested.
    """
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture
async def db_client(
    tmp_path: Path,
) -> AsyncIterator[tuple[TestClient, async_sessionmaker[AsyncSession]]]:
    """A `TestClient` whose `get_session` dependency is overridden to point at
    a fresh, per-test SQLite database, plus the session factory backing it
    (for a test to seed rows before making a request).

    The auth routes are the first in this suite that touch the database.
    `app.db.get_engine()` is a process-wide singleton, built once from
    `get_settings().database_url` and cached forever after — it never
    revisits `DATABASE_URL` on a later call, so pointing different tests at
    different scratch databases by mutating env vars would not work once
    another test has already triggered that first build. FastAPI's
    `dependency_overrides` sidesteps the singleton entirely instead: this
    fixture's own engine/session factory never goes near
    `app.db.get_engine`, so nothing here mutates process-wide state another
    test might rely on.

    Mirrors `tests/conftest.py`'s `session` fixture (`Base.metadata.create_all`
    rather than running Alembic — `tests/test_migrations.py` already
    guards schema drift between the two) and a real on-disk file rather than
    `:memory:`, for the same reason: pooled connections must all see the
    same database.
    """
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/api-test.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)

    async def _override_get_session() -> AsyncIterator[AsyncSession]:
        async with factory() as db_session:
            yield db_session

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    with TestClient(app) as test_client:
        yield test_client, factory

    await engine.dispose()
