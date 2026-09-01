"""Tests for the real Bitbucket Data Center client
(``app/adapters/bitbucket/client.py``).

Happy-path and typed-absence cases round-trip over real HTTP against
``fakes/bitbucket``. The failure-taxonomy cases a running fake cannot
produce on purpose use ``httpx.MockTransport``.
"""

from __future__ import annotations

import httpx
import pytest

from app.adapters.bitbucket.client import BitbucketHttpClient
from app.adapters.errors import UpstreamResponseError, UpstreamTimeout, UpstreamUnavailable
from app.adapters.protocols import SourceRepository
from tests.adapters.support import (
    BITBUCKET_BASE_URL,
    capturing,
    raising,
    require_reachable,
    responding,
)

REPO = "PAY/payments-api"
REF = "release/2026.09"
_SECRET = "bitbucket-pat-1a2b3c4d5e6f7a8b"


@pytest.fixture
def client() -> BitbucketHttpClient:
    require_reachable(BITBUCKET_BASE_URL)
    return BitbucketHttpClient(base_url=BITBUCKET_BASE_URL, token=_SECRET)


def test_bitbucket_http_client_satisfies_the_protocol(client: BitbucketHttpClient) -> None:
    assert isinstance(client, SourceRepository)


async def test_search_symbol_finds_the_known_reference(client: BitbucketHttpClient) -> None:
    hits = await client.search_symbol(REPO, "StringSubstitutor", REF)
    assert len(hits) == 2
    assert all(hit.path.endswith("PaymentService.java") for hit in hits)
    assert all(hit.line > 0 for hit in hits)


async def test_search_symbol_strips_the_vendors_html_highlight_markup(
    client: BitbucketHttpClient,
) -> None:
    """Bitbucket Server wraps a hit's matched region in ``<em>`` — a real
    client must strip it, not read it as plain text (see
    ``fakes/bitbucket/main.py``'s ``_highlight``)."""
    hits = await client.search_symbol(REPO, "StringSubstitutor", REF)
    assert all("<em>" not in hit.snippet and "</em>" not in hit.snippet for hit in hits)
    assert any("StringSubstitutor" in hit.snippet for hit in hits)


async def test_search_symbol_no_hits_for_an_absent_symbol(client: BitbucketHttpClient) -> None:
    assert await client.search_symbol(REPO, "SomethingNotInTheTree", REF) == []


async def test_search_symbol_filters_hits_to_the_requested_repo() -> None:
    """The fake's search is server-wide; this client must not attribute a
    hit from a different repo to the one the caller asked about."""
    body = {
        "query": "StringSubstitutor",
        "code": {
            "count": 1,
            "values": [
                {
                    "file": {
                        "path": {"toString": "src/Other.java"},
                        "project": {"key": "OTHER"},
                        "repository": {"slug": "other-repo"},
                    },
                    "hitContexts": [[{"line": 1, "text": "StringSubstitutor"}]],
                }
            ],
        },
    }
    client = BitbucketHttpClient(
        base_url=BITBUCKET_BASE_URL, token=_SECRET, transport=responding(200, body)
    )
    assert await client.search_symbol(REPO, "StringSubstitutor", REF) == []


async def test_file_round_trips_source_content(client: BitbucketHttpClient) -> None:
    content = await client.file(
        REPO, "src/main/java/com/example/payments/PaymentService.java", REF
    )
    assert content is not None
    assert b"StringSubstitutor" in content


async def test_file_404_is_a_typed_absence(client: BitbucketHttpClient) -> None:
    assert await client.file(REPO, "does/not/exist.java", REF) is None


async def test_file_unknown_repository_is_also_a_typed_absence(client: BitbucketHttpClient) -> None:
    assert await client.file("NOPE/nonexistent-repo", "pom.xml", REF) is None


async def test_repo_must_be_project_slash_repo(client: BitbucketHttpClient) -> None:
    with pytest.raises(ValueError, match="projectKey"):
        await client.file("payments-api", "pom.xml", REF)


async def test_5xx_raises_a_typed_error() -> None:
    transport = responding(500, {"error": "internal"})
    client = BitbucketHttpClient(base_url=BITBUCKET_BASE_URL, token=_SECRET, transport=transport)
    with pytest.raises(UpstreamResponseError) as exc_info:
        await client.search_symbol(REPO, "x", REF)
    assert exc_info.value.status_code == 500


async def test_timeout_raises_a_typed_error() -> None:
    transport = raising(lambda request: httpx.ReadTimeout("simulated", request=request))
    client = BitbucketHttpClient(base_url=BITBUCKET_BASE_URL, token=_SECRET, transport=transport)
    with pytest.raises(UpstreamTimeout):
        await client.search_symbol(REPO, "x", REF)


async def test_connection_failure_raises_a_typed_error() -> None:
    transport = raising(lambda request: httpx.ConnectError("simulated", request=request))
    client = BitbucketHttpClient(base_url=BITBUCKET_BASE_URL, token=_SECRET, transport=transport)
    with pytest.raises(UpstreamUnavailable):
        await client.search_symbol(REPO, "x", REF)


async def test_no_secret_appears_in_exception_or_logs_on_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport, seen = capturing(500, {"error": "internal"})
    client = BitbucketHttpClient(base_url=BITBUCKET_BASE_URL, token=_SECRET, transport=transport)

    with caplog.at_level("DEBUG"), pytest.raises(UpstreamResponseError) as exc_info:
        await client.search_symbol(REPO, "x", REF)

    assert seen[0]["authorization"] == f"Bearer {_SECRET}"

    assert _SECRET not in str(exc_info.value)
    assert _SECRET not in repr(exc_info.value)
    assert _SECRET not in caplog.text
