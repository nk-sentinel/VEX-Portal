"""Login, logout, and identity — ``POST /api/auth/login``,
``POST /api/auth/logout``, ``GET /api/auth/me``.

**``GET /api/auth/me`` returns the roles the server believes, never what the
client claims.** It reads its answer straight from ``get_current_session``
(``app/api/deps.py``), which only ever returns a payload that verified
against ``settings.session_secret`` — there is no code path here that lets
a request argue its own roles. The Angular screens call this endpoint to
decide what to render, and that is a convenience, never the enforcement
point: every action endpoint enforces its own capability independently
(``app/api/deps.py``'s ``requires(Capability)``), so a stale or
client-side-only belief about roles can never grant an action, only mis-render a
screen until the next ``/me`` call corrects it.

**The failed-login response never distinguishes an unknown username from a
wrong password** — same 401, same message, and (per
``app/auth/local.py``) comparable time either way. Login failure detail
lives in server logs an operator can read, never in the response body.

**The session secret cannot appear here.** The cookie value is an
``itsdangerous``-signed token (``app/middleware/session.py``); the raw
secret itself is never read out of ``settings.session_secret`` by this
module — only handed, still wrapped in a ``SecretStr``, to
``create_session_cookie``/``read_session_cookie``, which are the only two
functions that ever call ``.get_secret_value()`` on it.

**A downed or misconfigured directory is not the same failure as a bad
password.** ``LdapAuthProvider`` (``app/auth/ldap.py``) raises
``LdapUnavailable`` — never returns ``None`` — when the directory itself
could not be reached, bound to, or queried; ``login`` turns that into 503,
distinct from the 401 a rejected credential gets. Collapsing the two would
mean a downed AD server looks, from the outside, identical to one person
mistyping their password.
"""

from __future__ import annotations

from collections.abc import Iterable

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_session
from app.auth.ldap import LdapUnavailable
from app.auth.providers import get_auth_provider
from app.config import Settings, get_settings
from app.db import get_session
from app.middleware.session import SESSION_COOKIE_NAME, SessionData, create_session_cookie
from app.repos.models import Role

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class IdentityResponse(BaseModel):
    """The caller's identity and roles, as the server believes them —
    never anything the client supplied. See this module's docstring.
    """

    username: str
    roles: list[str]


def _identity(username: str, roles: Iterable[Role]) -> IdentityResponse:
    return IdentityResponse(username=username, roles=sorted(role.value for role in roles))


@router.post("/login", response_model=IdentityResponse)
async def login(
    body: LoginRequest,
    response: Response,
    settings: Settings = Depends(get_settings),
    db_session: AsyncSession = Depends(get_session),
) -> IdentityResponse:
    provider = get_auth_provider(settings, db_session)
    try:
        user = await provider.authenticate(body.username, body.password)
    except LdapUnavailable as exc:
        # The directory itself is unreachable/misconfigured — a different
        # fact from "this credential was rejected", and worth a different
        # status code so it is not mistaken for one. The response stays
        # generic; exc's detail (never a secret — see app/auth/ldap.py) is
        # for whoever reads the exception chain, not for the caller.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authentication service unavailable",
        ) from exc
    if user is None:
        # Deliberately identical whether the username exists or not — see
        # this module's docstring and app/auth/local.py.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid username or password"
        )

    cookie_value = create_session_cookie(user, settings=settings)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        cookie_value,
        httponly=True,
        samesite="lax",
        secure=settings.session_cookie_secure,
        path="/",
    )
    return _identity(user.username, user.roles)


@router.post("/logout")
async def logout(response: Response) -> dict[str, str]:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@router.get("/me", response_model=IdentityResponse)
async def me(session: SessionData = Depends(get_current_session)) -> IdentityResponse:
    return _identity(session.username, session.roles)


__all__ = ["router"]
