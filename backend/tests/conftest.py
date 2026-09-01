"""Shared fixtures.

Only ``tests/repos`` currently asks for a database session, and pytest only
builds a fixture when a test declares it by parameter name — the
evidence-engine suites under ``tests/artifact``, ``tests/domain``,
``tests/evidence``, and ``tests/provenance`` take no fixtures and never touch
this file, so nothing changes for them.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import make_engine, session_factory
from app.repos.models import Base


@pytest.fixture
async def session(tmp_path: Path) -> AsyncIterator[AsyncSession]:
    """An async session bound to a fresh on-disk SQLite database.

    Bound to a real file rather than ``:memory:`` so that pooled connections
    (used by ``make_engine``) all see the same database — an in-memory SQLite
    database is private to the connection that created it.
    """
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/test.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = session_factory(engine)
    async with factory() as db_session:
        yield db_session

    await engine.dispose()
