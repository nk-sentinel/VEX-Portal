"""Guards against schema drift between the ORM models and the Alembic migrations.

`tests/conftest.py`'s `session` fixture builds tables straight from
`Base.metadata.create_all` — convenient for every other test file, but it means
a model added without a matching migration would pass the entire suite and
still fail (or worse, silently omit a column the audit trail depends on) the
moment it hit a real deployment, where only `alembic upgrade head` runs. These
tests run the actual migrations against a scratch database and check the
result against `Base.metadata` directly, so that drift is caught here instead.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.repos.models import Base

_BACKEND_ROOT = Path(__file__).resolve().parents[1]

#: Alembic creates this table itself to track the applied revision; it is
#: never part of `Base.metadata` and must not be mistaken for drift.
_ALEMBIC_BOOKKEEPING_TABLES = {"alembic_version"}


def _alembic_config(db_path: Path) -> Config:
    """A Config pointed at this repo's migrations and a scratch database.

    `script_location` is forced to an absolute path rather than left as the
    relative value in `alembic.ini`, so this works no matter what directory
    pytest is invoked from.
    """
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    return cfg


async def _table_names(db_path: Path) -> set[str]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        async with engine.connect() as conn:
            return await conn.run_sync(lambda sync_conn: set(inspect(sync_conn).get_table_names()))
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_migration_creates_every_table_the_models_declare(tmp_path: Path) -> None:
    # Guards the usual drift: a model added without a migration works in tests
    # (metadata.create_all) and fails on a real deployment.
    db_path = tmp_path / "migrate.db"
    command.upgrade(_alembic_config(db_path), "head")

    table_names = await _table_names(db_path)
    expected = set(Base.metadata.tables.keys())

    missing = expected - table_names
    assert not missing, f"migrations never created: {missing}"

    extra = table_names - expected - _ALEMBIC_BOOKKEEPING_TABLES
    assert not extra, f"migrations created tables no model declares: {extra}"


@pytest.mark.asyncio
async def test_downgrade_then_upgrade_is_clean(tmp_path: Path) -> None:
    # A downgrade() that drops tables in the wrong order, or forgets one,
    # either raises outright (a foreign key still points at a dropped table)
    # or leaves the database unable to reach head again cleanly.
    db_path = tmp_path / "roundtrip.db"
    cfg = _alembic_config(db_path)
    expected = set(Base.metadata.tables.keys())

    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")

    after_downgrade = await _table_names(db_path)
    assert after_downgrade & expected == set(), (
        f"downgrade left model tables behind: {after_downgrade & expected}"
    )

    command.upgrade(cfg, "head")

    after_reupgrade = await _table_names(db_path)
    assert expected <= after_reupgrade, (
        f"re-upgrade after downgrade lost: {expected - after_reupgrade}"
    )
