"""Shared test plumbing for the real adapter client tests.

Not a ``test_*.py`` module — pytest never collects this file directly, only
imports it. Two things live here:

1. Constants and a reachability guard for the four live fake processes
   (``docker compose up -d`` starts them on 9101-9104; see
   ``fakes/README.md`` and ``compose.yaml``) — the happy-path and
   typed-absence tests round-trip against these over real HTTP.
2. ``httpx.MockTransport`` builders for the failure-taxonomy cases none of
   the fakes can produce on purpose (a 500, a hung connection, a refused
   connection): built into the *same* real client class under test, not a
   second implementation, so what is exercised is still the real client's
   own retry/timeout/error-translation code — just fed a synthetic
   transport instead of a live socket.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

IQ_BASE_URL = "http://localhost:9101"
JFROG_BASE_URL = "http://localhost:9102"
BITBUCKET_BASE_URL = "http://localhost:9103"
BEDROCK_BASE_URL = "http://localhost:9104"


def require_reachable(base_url: str) -> None:
    """Skip the test if the live fake at ``base_url`` is not running.

    Any HTTP response (even a 404) proves reachability; only a transport-level
    failure to connect means the fake is not up.
    """
    try:
        httpx.get(base_url, timeout=1.0)
    except httpx.HTTPError:
        pytest.skip(f"{base_url} is not reachable — start it with `docker compose up -d`")


def responding(status_code: int, json_body: object = None) -> httpx.MockTransport:
    """A transport that answers every request with a fixed status/body."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=json_body if json_body is not None else {})

    return httpx.MockTransport(handler)


def raising(make_exc: Callable[[httpx.Request], Exception]) -> httpx.MockTransport:
    """A transport that raises on every request — for simulating a timeout or
    a connection failure, which nothing under this project's control can
    make a real, running fake do on purpose."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise make_exc(request)

    return httpx.MockTransport(handler)


def capturing(
    status_code: int, json_body: object = None
) -> tuple[httpx.MockTransport, list[httpx.Headers]]:
    """Like :func:`responding`, but also records every request's headers —
    used to prove a secret-leak test is discriminating: the token really was
    sent, so a passing "no secret leaked" assertion means something.
    """
    seen: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        return httpx.Response(status_code, json=json_body if json_body is not None else {})

    return httpx.MockTransport(handler), seen
