"""Tests for `app/middleware/session.py` — signed, stateless session cookies.

Expiry is tested by jumping `time.time()` far into the future rather than
sleeping or reaching into module internals: itsdangerous computes
`age = now - signed_timestamp` and rejects when `age > max_age`, so a `now`
decades ahead of the signed timestamp is expired under any
`session_ttl_hours` value, deterministically, with no real time needing to
pass. This also means the test proves expiry against whatever TTL is
actually configured, rather than a value the test controls directly.
"""

from __future__ import annotations

import time

from app.auth.providers import AuthenticatedUser
from app.config import Settings
from app.middleware.session import SessionData, create_session_cookie, read_session_cookie
from app.repos.models import Role

_FAR_FUTURE_OFFSET_SECONDS = 100 * 365 * 24 * 60 * 60  # +100 years


def _settings(secret: str = "a-test-only-session-secret", **overrides: object) -> Settings:
    return Settings(_env_file=None, session_secret=secret, **overrides)  # type: ignore[arg-type]


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

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + _FAR_FUTURE_OFFSET_SECONDS)

    assert read_session_cookie(cookie, settings=settings) is None


def test_session_ttl_is_read_from_settings_not_hardcoded(monkeypatch):
    # A regression test for exactly the shape of bug that made TTL a
    # hardcoded constant in the first place: prove read_session_cookie
    # actually consults settings.session_ttl_hours rather than a fixed
    # value, by giving two sessions different TTLs and jumping the clock to
    # a point between them.
    short_lived = _settings(session_ttl_hours=1)
    long_lived = _settings(session_ttl_hours=24)
    user = AuthenticatedUser(username="alice", roles=frozenset())
    short_cookie = create_session_cookie(user, settings=short_lived)
    long_cookie = create_session_cookie(user, settings=long_lived)

    real_time = time.time
    ten_hours_later = real_time() + 10 * 60 * 60
    monkeypatch.setattr(time, "time", lambda: ten_hours_later)

    assert read_session_cookie(short_cookie, settings=short_lived) is None
    assert read_session_cookie(long_cookie, settings=long_lived) is not None


def test_session_ttl_hours_defaults_to_twelve():
    assert Settings(_env_file=None).session_ttl_hours == 12


def test_the_session_secret_never_appears_in_the_cookie_value():
    settings = _settings()
    user = AuthenticatedUser(username="alice", roles=frozenset())

    cookie = create_session_cookie(user, settings=settings)

    assert "a-test-only-session-secret" not in cookie
