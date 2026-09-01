"""Database engine.

SQLite needs two things asked for explicitly on every connection. Foreign keys
are off by default, so without the pragma a finding can outlive the assessment
it belongs to and the audit trail grows holes nothing detects. WAL lets readers
work while a write is in flight, which is what makes a single-file database
usable for a review queue several people are watching while determinations
are being committed.

SQLite applies both pragmas per connection, not once per process, so they are
set from a `connect` event that fires for every physical DBAPI connection the
pool opens — not just the first one. The pragmas are also SQLite-specific
syntax: they are applied only when the target dialect resolves to sqlite, so a
Postgres connection string keeps working unmodified. A server database has to
stay reachable as a connection-string change alone, and an unconditional
pragma would break that the moment the string points elsewhere.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy import event, make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings

_SQLITE_DIALECT = "sqlite"


def _is_sqlite(url: str) -> bool:
    """Resolve `url`'s dialect name without requiring its driver to be installed.

    Checked off the URL string rather than a constructed engine:
    `make_url(...).get_dialect()` only inspects dialect metadata, so this
    works even for a dialect (e.g. postgresql+asyncpg) whose driver package
    isn't present in this environment.
    """
    return make_url(url).get_dialect().name == _SQLITE_DIALECT


def make_engine(url: str) -> AsyncEngine:
    """Build an async engine, applying SQLite's pragmas only when the dialect calls for them."""
    engine = create_async_engine(url, echo=False, future=True)

    if _is_sqlite(url):
        database = engine.url.database
        if database and database != ":memory:":
            # A fresh checkout has no `data/` directory yet, and SQLite will
            # not create a missing parent directory on its own.
            Path(database).parent.mkdir(parents=True, exist_ok=True)

        @event.listens_for(engine.sync_engine, "connect")
        def _apply_pragmas(dbapi_connection: object, _record: object) -> None:
            cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

    return engine


def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Build a session factory bound to `engine`.

    Sessions don't expire objects on commit: a determination or audit row is
    typically read again right after it's written (e.g. to return the created
    record to a caller), and expiring it would force a needless reload.
    """
    return async_sessionmaker(engine, expire_on_commit=False)


_engine: AsyncEngine | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = make_engine(get_settings().database_url)
    return _engine


async def get_session() -> AsyncIterator[AsyncSession]:
    factory = session_factory(get_engine())
    async with factory() as session:
        yield session
