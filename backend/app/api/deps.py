"""FastAPI dependencies for reading the caller's identity.

:func:`get_current_session` answers "who is this, according to the server"
by verifying the session cookie's signature — never by trusting anything
else the request claims. This is what makes ``GET /api/auth/me``
(``app/api/auth.py``) trustworthy: it returns exactly what this function
returns, nothing the client supplied.

**401, not 403, for a missing or invalid session.** "The server does not
know who you are" is a different fact from 403's "the server knows exactly
who you are, and you may not do this" — the screens react differently to
the two (401 sends you to the login screen; 403 does not), so collapsing
them into one status would be a real regression for the client, not just an
imprecise API. (403 itself has no dependency here yet — Task 3 adds
``requires(Capability)``, built on top of this function, to this same
module.)
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status

from app.config import Settings, get_settings
from app.middleware.session import SESSION_COOKIE_NAME, SessionData, read_session_cookie


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


__all__ = ["get_current_session"]
