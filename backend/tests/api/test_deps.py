"""Tests for `app/api/deps.py`'s `requires(Capability)` FastAPI dependency.

A tiny standalone app, built only for this suite. No route in Tasks 1-3
performs a guarded action yet — assessments and review endpoints land in
later tasks and will depend on `requires(...)` themselves — so this tests
the dependency's own wiring directly: does it read the session the way
`app/api/auth.py` sets it, and does it produce 401 vs 403 for the right
reasons.
"""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.deps import requires
from app.auth.providers import AuthenticatedUser
from app.config import Settings, get_settings
from app.middleware.session import SESSION_COOKIE_NAME, SessionData, create_session_cookie
from app.repos.models import Role
from app.services.authorization import Capability

_SETTINGS = Settings(_env_file=None, session_secret="deps-test-secret")


def _build_app() -> FastAPI:
    app = FastAPI()
    app.dependency_overrides[get_settings] = lambda: _SETTINGS

    @app.get("/queue")
    async def queue(
        session: SessionData = Depends(requires(Capability.VIEW_QUEUE)),
    ) -> dict[str, str]:
        return {"username": session.username}

    @app.post("/rules")
    async def rules(
        session: SessionData = Depends(requires(Capability.MANAGE_RULES)),
    ) -> dict[str, str]:
        return {"username": session.username}

    return app


def _client_as(*roles: Role) -> TestClient:
    client = TestClient(_build_app())
    if roles:
        cookie = create_session_cookie(
            AuthenticatedUser(username="tester", roles=frozenset(roles)), settings=_SETTINGS
        )
        client.cookies.set(SESSION_COOKIE_NAME, cookie)
    return client


@pytest.mark.parametrize("role", [Role.REVIEWER, Role.APPROVER, Role.AUDITOR])
def test_view_queue_admits_exactly_its_roles(role):
    assert _client_as(role).get("/queue").status_code == 200


@pytest.mark.parametrize("role", [Role.REQUESTER, Role.RISK_MANAGER, Role.ADMIN])
def test_view_queue_rejects_the_rest(role):
    response = _client_as(role).get("/queue")
    assert response.status_code == 403


def test_unauthenticated_request_is_401_not_403():
    # No session at all is a different fact from "authenticated but lacking
    # the capability" — the screens react differently to the two.
    response = _client_as().get("/queue")
    assert response.status_code == 401


def test_an_invalid_session_cookie_is_401_not_403():
    client = TestClient(_build_app())
    client.cookies.set(SESSION_COOKIE_NAME, "not-a-real-session-token")

    assert client.get("/queue").status_code == 401


def test_manage_rules_is_admin_only():
    assert _client_as(Role.ADMIN).post("/rules").status_code == 200
    assert _client_as(Role.REVIEWER).post("/rules").status_code == 403
    assert _client_as(Role.APPROVER).post("/rules").status_code == 403


def test_holding_the_capability_alongside_unrelated_roles_still_admits():
    response = _client_as(Role.REQUESTER, Role.APPROVER).get("/queue")
    assert response.status_code == 200


def test_a_successful_request_still_reflects_the_authenticated_identity():
    response = _client_as(Role.AUDITOR).get("/queue")
    assert response.json() == {"username": "tester"}
