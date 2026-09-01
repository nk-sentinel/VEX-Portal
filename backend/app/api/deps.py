"""FastAPI dependencies for the identity and capability boundary.

Two dependencies, and every future route that guards an action depends on
one of them (directly, or through ``requires``):

* :func:`get_current_session` answers "who is this, according to the
  server" by verifying the session cookie's signature — never by trusting
  anything else the request claims. This is what makes ``GET /api/auth/me``
  (``app/api/auth.py``) trustworthy: it returns exactly what this function
  returns, nothing the client supplied.
* :func:`requires` builds a per-capability dependency. **Authorisation is
  server-side, always** — the client (the Angular screens) calls
  ``GET /api/auth/me`` to decide what to *render*, which is a convenience,
  never the enforcement point. Every endpoint that performs a sensitive
  action must depend on ``requires(...)`` itself; a route that skips it
  because "the screen already hid the button" is exactly the gap this
  dependency exists to close.

**401 vs 403 is deliberate and load-bearing, not cosmetic.** No session, or
an invalid one, is 401: "the server does not know who you are" — a
different fact from 403, "the server knows exactly who you are, and you may
not do this." The screens react differently to the two (401 sends you to
the login screen; 403 does not), so collapsing them into one status would
be a real regression for the client, not just an imprecise API.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, HTTPException, Request, status

from app.config import Settings, get_settings
from app.middleware.session import SESSION_COOKIE_NAME, SessionData, read_session_cookie
from app.services.authorization import Capability, has_capability


async def get_current_session(
    request: Request, settings: Settings = Depends(get_settings)
) -> SessionData:
    """The caller's session, decoded and signature-verified.

    Raises 401 for a missing, tampered, or expired session — see this
    module's docstring on why that is 401 and not 403.
    """
    session = read_session_cookie(request.cookies.get(SESSION_COOKIE_NAME), settings=settings)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not authenticated")
    return session


def requires(capability: Capability) -> Callable[..., Awaitable[SessionData]]:
    """Build a dependency admitting only a caller whose session holds a role
    granting ``capability``.

    Checks a capability, never a role, at the call site — see
    ``app/services/authorization.py``'s module docstring for why. This
    dependency alone is *not* sufficient for an action with a
    separation-of-duties rule (committing a determination): it only
    confirms the actor holds a role that can act in general, never anything
    about the specific record being acted on. See
    ``app/services/authorization.py``'s ``assert_may_commit_own_determination``
    for the check that is.
    """

    async def _dependency(session: SessionData = Depends(get_current_session)) -> SessionData:
        if not has_capability(session.roles, capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing capability: {capability.value}",
            )
        return session

    return _dependency


__all__ = ["get_current_session", "requires"]
