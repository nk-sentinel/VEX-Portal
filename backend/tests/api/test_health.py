"""`/health` must let a viewer tell a fake-backed instance from a real one at a
glance, and must never leak a secret — it is the most-requested, least-guarded
route in any service.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import create_app


def test_health_reports_adapter_mode_so_nobody_mistakes_fake_for_real(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["adapter_mode"] in {"fake", "real"}


def test_health_never_leaks_a_secret(client):
    assert "token" not in client.get("/health").text.lower()


def test_health_adapter_mode_tracks_settings_not_a_hardcoded_value(monkeypatch):
    # The two tests above pass even if the route hardcodes "fake" — {"fake",
    # "real"} contains "fake". Flip the configured mode and confirm the route
    # actually reads it, since a hardcoded value here is exactly how someone
    # ends up demoing against fakes while believing they're looking at
    # production.
    monkeypatch.setenv("ADAPTER_MODE", "real")
    monkeypatch.setenv("IQ_BASE_URL", "https://iq.example.internal")
    monkeypatch.setenv("JFROG_BASE_URL", "https://artifactory.example.internal")
    monkeypatch.setenv("BITBUCKET_BASE_URL", "https://bitbucket.example.internal")
    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as real_mode_client:
            body = real_mode_client.get("/health").json()
        assert body["adapter_mode"] == "real"
    finally:
        get_settings.cache_clear()


def test_health_reports_the_installed_package_version(client):
    # A hardcoded version string drifts from pyproject.toml the moment one is
    # bumped without the other. Confirm it's read from package metadata.
    from importlib.metadata import version

    body = client.get("/health").json()
    assert body["version"] == version("vex-portal")
