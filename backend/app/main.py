"""FastAPI application factory.

`/health` exists to answer one question at a glance: is this instance talking
to the fake stand-ins for Nexus IQ, JFrog, Bitbucket and Bedrock, or to the
real systems? A fake-backed instance and a real one are otherwise
indistinguishable from the outside, and that ambiguity is how someone ends up
demoing against fakes while believing they are looking at production data, or
treating a real instance as a fake one and taking an action they would not
otherwise take. `/health` names the adapter mode explicitly so nobody has to
guess.

`/health` reports only `status`, `adapter_mode` and `version` — never a
settings dump. It is the most-requested, least-guarded endpoint in any
service, and a settings dump there is how a token ends up in a monitoring
system that scrapes it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import version as package_version

from fastapi import FastAPI

from app.config import get_settings
from app.db import get_engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    await get_engine().dispose()


def create_app() -> FastAPI:
    """Build a fresh FastAPI application.

    A factory rather than a module-level singleton so tests can construct an
    independent app per test (each with its own lifespan run) instead of
    sharing one process-wide instance.
    """
    app = FastAPI(title="VEX Portal", lifespan=lifespan)

    @app.get("/health")
    async def health() -> dict[str, str]:
        settings = get_settings()
        return {
            "status": "ok",
            "adapter_mode": settings.adapter_mode.value,
            "version": package_version("vex-portal"),
        }

    return app


app = create_app()
