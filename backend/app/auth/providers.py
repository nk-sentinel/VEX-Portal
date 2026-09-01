"""The authentication boundary: exactly one way in, chosen by config.

Two implementations sit behind one ``AuthProvider`` Protocol so nothing
downstream — the login route, the session layer — needs to know whether a
credential was checked against the local ``user`` table
(``app/auth/local.py``) or against LDAP/AD (``app/auth/ldap.py``).
``get_auth_provider`` is the one place that choice is made, mirroring how
``app/adapters/factory.py`` chooses which concrete adapter backs each
external system — with one difference: a database-backed check needs the
same per-request ``AsyncSession`` everything else in the request uses, so
(unlike the stateless HTTP adapters) ``get_auth_provider`` takes one
alongside ``settings``.

``AuthenticatedUser`` never carries a password hash, an LDAP bind password,
or any other secret — it is the only shape either provider is allowed to
hand back, and it is what flows into the signed session cookie
(``app/middleware/session.py``) and the ``GET /api/auth/me`` response. If a
field does not belong in a response, it does not belong on this dataclass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import AuthProviderKind, Settings, get_settings
from app.repos.models import Role


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """The result of a successful authentication. Carries no secret."""

    username: str
    roles: frozenset[Role]


@runtime_checkable
class AuthProvider(Protocol):
    """Check one username/password pair.

    Returns ``None`` on any failure — unknown username, wrong password, a
    directory that is unreachable in a way that should be treated as "this
    credential did not check out" rather than raised. Implementations must
    not distinguish "unknown username" from "wrong password" by taking less
    time on the former: see ``app/auth/local.py``'s module docstring for why
    that distinction, even leaked only through timing, is a real hole for
    this portal's user list.
    """

    async def authenticate(self, username: str, password: str) -> AuthenticatedUser | None: ...


def get_auth_provider(settings: Settings | None, session: AsyncSession) -> AuthProvider:
    """Build the provider ``settings.auth_provider`` selects.

    Imports the concrete providers locally to avoid a module-level import
    cycle (``app/auth/local.py`` imports ``AuthenticatedUser`` from this
    module).
    """
    from app.auth.ldap import LdapAuthProvider
    from app.auth.local import LocalAuthProvider

    resolved = settings or get_settings()
    if resolved.auth_provider is AuthProviderKind.LDAP:
        return LdapAuthProvider(resolved)
    return LocalAuthProvider(session)


__all__ = ["AuthProvider", "AuthenticatedUser", "get_auth_provider"]
