import pytest
from sqlalchemy import text

from app.db import _is_sqlite, make_engine, session_factory


@pytest.mark.asyncio
async def test_foreign_keys_are_enforced(tmp_path):
    # SQLite ignores foreign keys unless asked, per connection. Without this a
    # finding can outlive the assessment it belongs to and the audit trail
    # develops holes nothing detects.
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/t.db")
    async with engine.connect() as conn:
        assert (await conn.execute(text("PRAGMA foreign_keys"))).scalar() == 1
    await engine.dispose()


@pytest.mark.asyncio
async def test_write_ahead_logging_is_enabled(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/t.db")
    async with engine.connect() as conn:
        assert (await conn.execute(text("PRAGMA journal_mode"))).scalar().lower() == "wal"
    await engine.dispose()


@pytest.mark.asyncio
async def test_pragmas_are_set_on_every_pooled_connection_not_just_the_first(tmp_path):
    # A pragma applied once at startup, against a single connection, leaves
    # the rest of the pool unprotected — SQLite pragmas are per-connection.
    # Hold two connections open at once to force the pool to open two
    # distinct physical DBAPI connections, and check both.
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/t.db")
    async with engine.connect() as first, engine.connect() as second:
        fk_first = (await first.execute(text("PRAGMA foreign_keys"))).scalar()
        fk_second = (await second.execute(text("PRAGMA foreign_keys"))).scalar()
        wal_first = (await first.execute(text("PRAGMA journal_mode"))).scalar()
        wal_second = (await second.execute(text("PRAGMA journal_mode"))).scalar()
    await engine.dispose()

    assert (fk_first, fk_second) == (1, 1)
    assert (wal_first.lower(), wal_second.lower()) == ("wal", "wal")


def test_sqlite_dialect_is_recognized_for_pragma_gating():
    assert _is_sqlite("sqlite+aiosqlite:///:memory:") is True


def test_non_sqlite_dialect_is_not_treated_as_sqlite():
    # The pragmas are SQLite-specific syntax. Applying them unconditionally
    # would break a Postgres connection string with an unknown pragma error,
    # so the schema and engine can no longer stay a connection-string change
    # away from a server database. Checked off the URL rather than a
    # constructed engine, since the asyncpg driver isn't installed here.
    assert _is_sqlite("postgresql+asyncpg://user:pass@localhost/db") is False


@pytest.mark.asyncio
async def test_session_factory_builds_working_sessions(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/t.db")
    factory = session_factory(engine)
    async with factory() as session:
        assert (await session.execute(text("SELECT 1"))).scalar() == 1
    await engine.dispose()
