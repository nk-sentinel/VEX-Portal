"""Signed, stateless session cookies.

The session is the cookie: everything ``GET /api/auth/me`` and
``app/api/deps.py``'s ``requires(Capability)`` dependency need — username
and roles — is serialised into the cookie value itself and signed with
``settings.session_secret`` via ``itsdangerous``. There is no server-side
session table to look up, so a session is valid exactly when its signature
verifies and it has not outlived ``_SESSION_MAX_AGE_SECONDS`` — nothing else
to keep in sync, and nothing else that could drift from what the cookie
says.

**This is why ``GET /api/auth/me`` can be trusted**: the payload this module
hands back came from unwrapping ``itsdangerous``'s signature, not from
anything the client sent as data. A client can present any cookie value it
likes, but it cannot produce one that verifies against
``settings.session_secret`` without knowing that secret — so the roles this
module returns are the roles the server itself put there at login, never
what a request merely claims.

``itsdangerous.BadSignature`` (raised for a tampered cookie) and its
subclass ``SignatureExpired`` (raised for a validly-signed but outlived one)
are both treated identically here: an invalid session, full stop, not
distinguished for the caller. Session TTL — 12 hours — is not called out
anywhere in ``app/config.py``; there is no setting for it in the brief this
task worked from, so it is a fixed constant here rather than an invented
setting. Flagged in the Task 1-3 report.
"""

from __future__ import annotations

from dataclasses import dataclass

from itsdangerous import BadSignature, URLSafeTimedSerializer

from app.auth.providers import AuthenticatedUser
from app.config import Settings
from app.repos.models import Role

#: The cookie's name on the wire.
SESSION_COOKIE_NAME = "vex_session"

#: itsdangerous salts the derived signing key by purpose, so a session
#: cookie's signature can never be replayed against some other signed value
#: this app might sign in the future for a different reason.
_SESSION_SALT = "vex-portal.session.v1"

#: A session is valid for 12 hours after login, then must be re-established.
#: Not derived from any setting — see this module's docstring.
_SESSION_MAX_AGE_SECONDS = 12 * 60 * 60


@dataclass(frozen=True, slots=True)
class SessionData:
    """What a valid session cookie decodes to: exactly what
    :class:`app.auth.providers.AuthenticatedUser` carries, and nothing a
    provider did not put there.
    """

    username: str
    roles: frozenset[Role]


def _serializer(settings: Settings) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.session_secret.get_secret_value(), salt=_SESSION_SALT)


def create_session_cookie(user: AuthenticatedUser, *, settings: Settings) -> str:
    """Sign ``user`` into a cookie value for ``POST /api/auth/login`` to set."""
    payload = {"username": user.username, "roles": sorted(role.value for role in user.roles)}
    return _serializer(settings).dumps(payload)


def read_session_cookie(cookie_value: str | None, *, settings: Settings) -> SessionData | None:
    """Verify and decode a session cookie value.

    Returns ``None`` — never raises — for a missing cookie, a tampered one,
    or one that has outlived ``_SESSION_MAX_AGE_SECONDS``: all three are
    "no valid session" from every caller's point of view.
    """
    if not cookie_value:
        return None
    try:
        payload = _serializer(settings).loads(cookie_value, max_age=_SESSION_MAX_AGE_SECONDS)
    except BadSignature:
        return None
    return SessionData(
        username=payload["username"], roles=frozenset(Role(value) for value in payload["roles"])
    )


__all__ = [
    "SESSION_COOKIE_NAME",
    "SessionData",
    "create_session_cookie",
    "read_session_cookie",
]
