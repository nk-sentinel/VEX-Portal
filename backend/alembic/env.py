"""Alembic environment.

Two departures from the default template, both required by this project.

**The database URL comes from ``app.config.get_settings().database_url`` by
default, never from a value checked into ``alembic.ini``.** Secrets and
infrastructure facts live in the environment, not in a checked-in file — the
same rule ``app/config.py`` follows for the app itself; ``alembic.ini``
carries no real ``sqlalchemy.url``. A caller may still override the URL the
normal Alembic way, by setting it on the ``Config`` object before invoking a
command (``config.set_main_option("sqlalchemy.url", ...)``) — this is how
``tests/test_migrations.py`` points migrations at a scratch, per-test
database instead of the real one. That is a supported override, not a
hardcoded value, and it only ever takes effect when a caller opts in.

**Migrations run over a synchronous engine, even though the app is async
(``aiosqlite``).** Alembic's migration runner is synchronous end to end; the
``-t async`` template papers over that by opening its own event loop inside
``run_migrations_online`` (``asyncio.run(...)``), which breaks the moment
migrations are invoked from code that is already inside a running loop —
exactly what ``tests/test_migrations.py`` does, calling
``alembic.command.upgrade`` from an ``async def`` test under
``pytest-asyncio``. A plain synchronous engine sidesteps that entirely and
needs no new dependency: stripping the async driver suffix off the
configured URL (``sqlite+aiosqlite`` -> ``sqlite``) lands on ``pysqlite``,
the standard library's own driver. A future Postgres deployment will need a
sync driver installed for this step alongside the async one the app uses at
runtime (``psycopg`` next to ``asyncpg``, say) — a one-time, well-understood
cost, not a dependency this task needs to add since only SQLite is in play
today.

One thing this file deliberately does *not* do: force ``PRAGMA
foreign_keys=ON`` the way ``app/db.py`` does for the running app. SQLite's
own recommended procedure for altering a table it cannot ``ALTER`` in place
(the exact case ``render_as_batch=True`` exists for below) is to rebuild it
with foreign key enforcement *off* — turning it on here would make a future
batch migration fail to drop a table that something else still references
mid-rebuild, for a pragma that buys nothing during a schema change.
"""

from __future__ import annotations

from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import make_url

from alembic import context
from app.config import get_settings
from app.repos.models import Base

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# What `alembic revision --autogenerate` diffs against, and what
# `render_as_batch` (set below) applies SQLite's rebuild-in-place strategy to.
target_metadata = Base.metadata


def _configured_database_url() -> str:
    """The database URL to migrate: an explicit override if the caller gave
    one, otherwise the app's own runtime setting.

    ``Config.get_main_option`` returns the override a caller set via
    ``set_main_option`` (what ``tests/test_migrations.py`` uses to point at a
    scratch database) — ``alembic.ini`` itself never supplies one, so absent
    an override this always falls through to ``get_settings().database_url``,
    the same URL the running app would connect with.
    """
    return config.get_main_option("sqlalchemy.url") or get_settings().database_url


def _sync_database_url() -> str:
    """`_configured_database_url`, forced onto a synchronous driver.

    See the module docstring: migrations run on a sync engine regardless of
    what driver the running app uses, so the async suffix (``+aiosqlite``,
    ``+asyncpg``, ...) is stripped in favour of each dialect's default sync
    driver.
    """
    url = make_url(_configured_database_url())
    sync_url = url.set(drivername=url.get_backend_name())

    if sync_url.get_backend_name() == "sqlite" and sync_url.database not in (None, ":memory:"):
        # Mirrors app.db.make_engine: a fresh checkout has no `data/`
        # directory yet, and SQLite will not create a missing parent
        # directory on its own.
        assert sync_url.database is not None  # narrowed by the `not in` check above
        Path(sync_url.database).parent.mkdir(parents=True, exist_ok=True)

    return str(sync_url)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    context.configure(
        url=_sync_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _sync_database_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        # SQLite cannot ALTER most things in place; without batch mode, any
        # future column change produces a migration that works on Postgres
        # and fails on SQLite.
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
