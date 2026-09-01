"""Tests for `app/api/auth.py` — POST /api/auth/login, POST /api/auth/logout,
GET /api/auth/me.
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest
from argon2 import PasswordHasher

from app.middleware.session import SESSION_COOKIE_NAME
from app.repos.models import Role, User

_PASSWORD = "correct horse battery staple"  # noqa: S105 - test fixture, not a real credential


async def _seed_user(
    factory,
    *,
    username: str = "alice",
    password: str = _PASSWORD,
    roles: Iterable[Role] = (Role.REVIEWER,),
) -> None:
    hasher = PasswordHasher()
    async with factory() as db_session:
        db_session.add(
            User(
                username=username,
                password_hash=hasher.hash(password),
                roles_json=[role.value for role in roles],
            )
        )
        await db_session.commit()


@pytest.mark.asyncio
async def test_login_with_correct_credentials_sets_a_session_cookie(db_client):
    client, factory = db_client
    await _seed_user(factory)

    response = client.post("/api/auth/login", json={"username": "alice", "password": _PASSWORD})

    assert response.status_code == 200
    assert SESSION_COOKIE_NAME in response.cookies
    body = response.json()
    assert body == {"username": "alice", "roles": ["reviewer"]}


@pytest.mark.asyncio
async def test_login_with_wrong_password_is_rejected(db_client):
    client, factory = db_client
    await _seed_user(factory)

    response = client.post("/api/auth/login", json={"username": "alice", "password": "wrong"})

    assert response.status_code == 401
    assert SESSION_COOKIE_NAME not in response.cookies


@pytest.mark.asyncio
async def test_login_with_unknown_username_gives_the_identical_response_as_wrong_password(
    db_client,
):
    # Same status, same body either way — an unknown username must not be
    # distinguishable from a known one with the wrong password by anything
    # the response says.
    client, factory = db_client
    await _seed_user(factory)

    known_wrong = client.post("/api/auth/login", json={"username": "alice", "password": "wrong"})
    unknown = client.post(
        "/api/auth/login", json={"username": "nobody-such-user", "password": "wrong"}
    )

    assert known_wrong.status_code == unknown.status_code == 401
    assert known_wrong.json() == unknown.json()


@pytest.mark.asyncio
async def test_me_returns_the_identity_and_roles_the_login_established(db_client):
    client, factory = db_client
    await _seed_user(factory, roles=(Role.REVIEWER, Role.APPROVER))
    client.post("/api/auth/login", json={"username": "alice", "password": _PASSWORD})

    response = client.get("/api/auth/me")

    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "alice"
    assert set(body["roles"]) == {"reviewer", "approver"}


@pytest.mark.asyncio
async def test_me_returns_the_servers_roles_not_anything_the_client_could_supply(db_client):
    # GET /me takes no request body/params at all — there is no field a
    # caller could set to influence the roles returned. This pins that down
    # explicitly: passing an unrelated body/query must not change the
    # answer.
    client, factory = db_client
    await _seed_user(factory, roles=(Role.REVIEWER,))
    client.post("/api/auth/login", json={"username": "alice", "password": _PASSWORD})

    response = client.request(
        "GET", "/api/auth/me", params={"roles": "admin"}, json={"roles": ["admin"]}
    )

    assert response.json()["roles"] == ["reviewer"]


@pytest.mark.asyncio
async def test_me_without_a_session_is_401_not_403(db_client):
    client, _factory = db_client

    response = client.get("/api/auth/me")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_logout_clears_the_session(db_client):
    client, factory = db_client
    await _seed_user(factory)
    client.post("/api/auth/login", json={"username": "alice", "password": _PASSWORD})
    assert client.get("/api/auth/me").status_code == 200

    logout_response = client.post("/api/auth/logout")
    assert logout_response.status_code == 200

    assert client.get("/api/auth/me").status_code == 401


@pytest.mark.asyncio
async def test_a_tampered_session_cookie_is_rejected(db_client):
    client, factory = db_client
    await _seed_user(factory)
    client.post("/api/auth/login", json={"username": "alice", "password": _PASSWORD})

    # Flip a character inside the payload segment (before the first "."),
    # never the token's last character — see
    # tests/test_middleware_session.py's `_tamper` for why a last-character
    # flip is not a reliable way to corrupt an itsdangerous signature.
    cookie_value = client.cookies[SESSION_COOKIE_NAME]
    payload, _, rest = cookie_value.partition(".")
    index = len(payload) // 2
    flipped = "a" if payload[index] != "a" else "b"
    tampered = payload[:index] + flipped + payload[index + 1 :] + "." + rest
    client.cookies.set(SESSION_COOKIE_NAME, tampered)

    response = client.get("/api/auth/me")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_the_session_secret_never_appears_in_any_response(db_client):
    client, factory = db_client
    await _seed_user(factory)

    login_response = client.post(
        "/api/auth/login", json={"username": "alice", "password": _PASSWORD}
    )
    me_response = client.get("/api/auth/me")
    bad_login_response = client.post(
        "/api/auth/login", json={"username": "alice", "password": "x"}
    )

    # Default dev secret from app/config.py's Settings — asserting the
    # actual configured value never surfaces, not a guess at its shape.
    for response in (login_response, me_response, bad_login_response):
        assert "dev-only-change-me" not in response.text


@pytest.mark.asyncio
async def test_login_response_never_contains_a_password_hash(db_client):
    client, factory = db_client
    await _seed_user(factory)

    response = client.post("/api/auth/login", json={"username": "alice", "password": _PASSWORD})

    assert "$argon2" not in response.text
    assert "password_hash" not in response.text
    assert "password" not in response.json()
