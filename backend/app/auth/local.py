"""Local, database-backed authentication.

**Why the dummy hash matters.** An early return for a username that is not
in the ``user`` table is the standard way a login endpoint turns into a
username oracle: a request for a real username pays argon2's full
verification cost before failing, a request for a nonexistent one returns
almost instantly, and the gap is trivially measurable over a network. This
portal's user list is the AppSec team and the app teams they serve — worth
not publishing by timing. ``_DUMMY_HASH`` exists so both paths always pay
the same argon2 cost: :meth:`LocalAuthProvider.authenticate` runs
``_hasher.verify`` against *some* hash, known-user or not, before it ever
looks at whether ``user`` came back ``None``.

Argon2's own random salt means every real password hash differs even for
the same password, so a fixed dummy hash does not reveal anything by being
reused across misses — it is only ever a comparison target, never compared
against anything else.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.providers import AuthenticatedUser
from app.repos.models import Role, User

_hasher = PasswordHasher()

#: Spent on every authenticate() call where the username does not exist, so
#: an unknown-username miss costs the same as a wrong-password miss. See
#: this module's docstring.
_DUMMY_HASH = _hasher.hash("no-such-user-comparison-password")  # noqa: S106 - not a real credential


class LocalAuthProvider:
    """Checks a username/password pair against the ``user`` table.

    Takes the request's own ``AsyncSession`` at construction, built fresh
    per request by ``app.auth.providers.get_auth_provider`` — unlike the
    stateless HTTP adapters ``app/adapters/factory.py`` builds, a database
    lookup needs the same per-request session everything else in the
    request uses.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def authenticate(self, username: str, password: str) -> AuthenticatedUser | None:
        user = await self._session.scalar(select(User).where(User.username == username))

        # Always verify against *some* hash, known-user or not — see this
        # module's docstring on why an early return here is a timing leak.
        password_hash = user.password_hash if user is not None else _DUMMY_HASH
        try:
            _hasher.verify(password_hash, password)
            password_ok = True
        except (VerificationError, InvalidHashError):
            # VerificationError covers a plain mismatch; InvalidHashError
            # covers a malformed/foreign hash. Neither is ever surfaced —
            # both are just "this credential did not check out".
            password_ok = False

        if user is None or not password_ok:
            return None

        return AuthenticatedUser(
            username=user.username, roles=frozenset(Role(value) for value in user.roles_json)
        )


__all__ = ["LocalAuthProvider"]
