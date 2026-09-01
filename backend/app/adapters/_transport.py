"""Shared request plumbing for the four httpx-backed adapter clients.

IQ, JFrog, Bitbucket and ELK all go through :func:`send` (Bedrock does not —
it goes through boto3, whose own ``botocore.config.Config`` carries its
timeout and retry; see ``app/adapters/llm/client.py``). Centralising this
here means all four clients share one bounded-timeout, bounded-retry, no-
secret-in-the-error policy instead of reimplementing (and risking drifting)
it four times.

Every adapter method funnels a request through here: a bounded number of
attempts, each within a bounded per-request timeout, retrying only
conditions that are plausibly transient — a connection failure, a timeout, a
5xx. A 4xx is never retried, since a repeat request gets the same answer and
retrying it would only spend an outage's worth of time on a question that
was already answered. This is also *why* an unbounded retry is dangerous
enough to ban outright: against a struggling Nexus IQ, an unbounded retry on
what looks transient turns one slow request into an outage the client itself
manufactures.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from app.adapters.errors import (
    AdapterError,
    UpstreamResponseError,
    UpstreamTimeout,
    UpstreamUnavailable,
)

#: Bounded per-request timeout. Connect and read are split because a slow
#: TCP handshake and a slow response body are different failure modes worth
#: distinguishing in a profiler, even though both surface as UpstreamTimeout.
DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)

#: Total attempts, including the first — i.e. up to two retries. Bounded so a
#: struggling upstream costs a bounded amount of caller time, never an
#: open-ended one.
MAX_ATTEMPTS = 3

_BACKOFF_SECONDS = 0.2

logger = logging.getLogger(__name__)


async def send(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    **kwargs: object,
) -> httpx.Response:
    """Send one request with a bounded retry over transient failures.

    Returns any response with ``status_code < 500`` — including a 4xx —
    without raising: whether a given 4xx is a typed absence or a typed error
    is a decision only the calling method can make (see
    ``app/adapters/errors.py``), so it is left to :func:`raise_for_status` or
    an explicit ``status_code == 404`` check at the call site, not decided
    here.
    """
    last_error: AdapterError | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = await client.request(method, url, **kwargs)  # type: ignore[arg-type]
        except httpx.TimeoutException:
            last_error = UpstreamTimeout(
                f"{method} {url} timed out after {attempt} attempt(s)"
            )
        except httpx.HTTPError:
            last_error = UpstreamUnavailable(
                f"{method} {url} could not be reached after {attempt} attempt(s)"
            )
        else:
            if response.status_code < 500:
                return response
            last_error = UpstreamResponseError(method, url, response.status_code)

        if attempt < MAX_ATTEMPTS:
            logger.info(
                "retrying %s %s (attempt %d/%d) after %s",
                method,
                url,
                attempt,
                MAX_ATTEMPTS,
                type(last_error).__name__,
            )
            await asyncio.sleep(_BACKOFF_SECONDS * attempt)

    logger.warning(
        "giving up on %s %s after %d attempt(s): %s", method, url, MAX_ATTEMPTS, last_error
    )
    if last_error is None:  # pragma: no cover - unreachable, MAX_ATTEMPTS >= 1
        raise AdapterError(f"{method} {url} failed for an unknown reason")
    raise last_error


def raise_for_status(method: str, path: str, response: httpx.Response) -> None:
    """Raise :class:`UpstreamResponseError` for any status the caller has not
    already handled as a typed absence.

    Call this only after a caller-specific ``status_code == 404`` absence
    check (where one applies) has already returned — everything that reaches
    here, including a 404 the caller does *not* treat as an absence, is a
    hard error.
    """
    if response.is_success:
        return
    raise UpstreamResponseError(method, path, response.status_code)


async def send_or_none(
    client: httpx.AsyncClient, method: str, path: str, **kwargs: object
) -> httpx.Response | None:
    """Send ``method path``, treating a 404 as a typed absence rather than an
    error.

    For calls whose Protocol method returns ``X | None`` — a resource that
    legitimately may not exist yet (see ``app/adapters/errors.py`` and each
    client's own docstring for which of its calls this applies to).
    """
    response = await send(client, method, path, **kwargs)
    if response.status_code == 404:
        return None
    raise_for_status(method, path, response)
    return response


async def send_required(
    client: httpx.AsyncClient, method: str, path: str, **kwargs: object
) -> httpx.Response:
    """Send ``method path``, treating a 404 as an error: the caller named
    this resource and it must exist."""
    response = await send(client, method, path, **kwargs)
    raise_for_status(method, path, response)
    return response


async def get_or_none(
    client: httpx.AsyncClient, path: str, **kwargs: object
) -> httpx.Response | None:
    """``send_or_none`` specialised to GET — the common case."""
    return await send_or_none(client, "GET", path, **kwargs)


async def get_required(client: httpx.AsyncClient, path: str, **kwargs: object) -> httpx.Response:
    """``send_required`` specialised to GET — the common case."""
    return await send_required(client, "GET", path, **kwargs)
