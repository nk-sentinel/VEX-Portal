"""Fixtures for the API test suite."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    """A `TestClient` bound to a fresh app instance, running the app's lifespan.

    Entered as a context manager so startup/shutdown handlers actually run —
    a bare `TestClient(create_app())` never fires them, which would leave the
    lifespan's engine-disposal path untested.
    """
    with TestClient(create_app()) as test_client:
        yield test_client
