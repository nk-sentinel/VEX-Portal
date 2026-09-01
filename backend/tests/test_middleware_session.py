"""Tests for `app/middleware/session.py` — signed, stateless session cookies.

Expiry is tested by monkeypatching `_SESSION_MAX_AGE_SECONDS` to a negative
value rather than sleeping: itsdangerous rejects when `age > max_age`, and a
negative `max_age` is already exceeded by any cookie's age (which can never
be negative), so this is deterministic regardless of how fast the test runs
— no real time needs to pass.
"""

from __future__ import annotations

from app.auth.providers import AuthenticatedUser
from app.config import Settings
from app.middleware import session as session_module
from app.middleware.session import SessionData, create_session_cookie, read_session_cookie
from app.repos.models import Role


def _settings(secret: str = "a-test-only-session-secret") -> Settings:
    return Settings(_env_file=None, session_secret=secret)


def _tamper(cookie: str) -> str:
    """Flip one character inside the payload segment (before the first
    ``.``), never the last character of the whole token.

    itsdangerous's format is ``payload.timestamp.signature``, base64 end to
    end. Flipping the *last* character of the signature segment is not
    reliable: a base64 group that does not end on a 3-byte boundary — true
    of a 20-byte HMAC-SHA1 digest — has trailing padding bits in its final
    character that never affect the decoded bytes, so an unlucky flip there
    can land on a different base64 symbol that decodes to the identical
    signature and passes verification anyway. Flipping a character inside
    the payload instead always changes the decoded JSON, which can never
    match a signature computed over the original bytes.
    """
    payload, _, rest = cookie.partition(".")
    index = len(payload) // 2
    flipped = "a" if payload[index] != "a" else "b"
    return payload[:index] + flipped + payload[index + 1 :] + "." + rest


def test_a_valid_cookie_round_trips_username_and_roles():
    settings = _settings()
    user = AuthenticatedUser(username="alice", roles=frozenset({Role.REVIEWER, Role.APPROVER}))

    cookie = create_session_cookie(user, settings=settings)
    result = read_session_cookie(cookie, settings=settings)

    assert result == SessionData(username="alice", roles=frozenset({Role.REVIEWER, Role.APPROVER}))


def test_missing_cookie_is_not_a_session():
    assert read_session_cookie(None, settings=_settings()) is None
    assert read_session_cookie("", settings=_settings()) is None


def test_a_tampered_cookie_is_rejected():
    settings = _settings()
    user = AuthenticatedUser(username="alice", roles=frozenset())
    cookie = create_session_cookie(user, settings=settings)

    assert read_session_cookie(_tamper(cookie), settings=settings) is None


def test_a_cookie_signed_with_a_different_secret_is_rejected():
    settings = _settings()
    other_settings = _settings(secret="a-completely-different-secret")
    user = AuthenticatedUser(username="alice", roles=frozenset())
    cookie = create_session_cookie(user, settings=settings)

    assert read_session_cookie(cookie, settings=other_settings) is None


def test_garbage_is_rejected_not_raised():
    assert read_session_cookie("not-a-valid-token-at-all", settings=_settings()) is None


def test_an_expired_session_is_rejected(monkeypatch):
    settings = _settings()
    user = AuthenticatedUser(username="alice", roles=frozenset())
    cookie = create_session_cookie(user, settings=settings)

    monkeypatch.setattr(session_module, "_SESSION_MAX_AGE_SECONDS", -1)

    assert read_session_cookie(cookie, settings=settings) is None


def test_the_session_secret_never_appears_in_the_cookie_value():
    settings = _settings()
    user = AuthenticatedUser(username="alice", roles=frozenset())

    cookie = create_session_cookie(user, settings=settings)

    assert "a-test-only-session-secret" not in cookie
