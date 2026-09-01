"""Tests for the real ELK client (``app/adapters/elk/client.py``).

**No live fake exists for this client** — unlike IQ/JFrog/Bitbucket/Bedrock,
ELK was never in scope for ``fakes/`` (no ``fake_elk_url`` in
``app/config.py``, no ELK fake in the Task 7 brief; see this module's own
docstring and the Task 8 report). Every case here, including the happy path,
runs against ``httpx.MockTransport`` instead of a live process — real
``httpx.AsyncClient`` request/response handling is exercised, but "answers
over real HTTP the way the other four are checked" is not. Flagged for the
plan owner in the Task 8 report.
"""

from __future__ import annotations

import httpx
import pytest

from app.adapters.elk.client import ElkHttpClient
from app.adapters.errors import UpstreamResponseError, UpstreamTimeout, UpstreamUnavailable
from app.adapters.protocols import ScanArchive
from tests.adapters.support import capturing, raising, responding

BASE_URL = "http://localhost:9105"  # no live process — MockTransport only
_SECRET = "elk-token-2f3e4d5c6b7a8f9e0d1c"


def _client(transport: httpx.MockTransport) -> ElkHttpClient:
    return ElkHttpClient(
        base_url=BASE_URL, token=_SECRET, index="sbom-scans-*", transport=transport
    )


def test_elk_http_client_satisfies_the_protocol() -> None:
    client = _client(responding(200, {"hits": {"hits": []}}))
    assert isinstance(client, ScanArchive)


async def test_sbom_for_scan_parses_a_hit_into_a_scan_record() -> None:
    body = {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "scan_id": "scan-42",
                        "components": [
                            {"purl": "pkg:maven/x/y@1.0", "sha1": "a" * 40},
                            {"purl": "pkg:maven/x/z@2.0", "sha1": "b" * 40},
                        ],
                        "cve_ids": ["CVE-2022-42889", "CVE-2021-44228"],
                    }
                }
            ]
        }
    }
    client = _client(responding(200, body))
    record = await client.sbom_for_scan("scan-42")
    assert record is not None
    assert record.scan_id == "scan-42"
    assert len(record.components) == 2
    assert record.cve_ids == ["CVE-2022-42889", "CVE-2021-44228"]


async def test_sbom_for_scan_zero_hits_is_a_typed_absence_without_a_404() -> None:
    """Elasticsearch's ``_search`` always answers 200, even for "no
    results" — this is a typed absence expressed through an empty
    ``hits.hits``, not through a status code."""
    client = _client(responding(200, {"hits": {"hits": []}}))
    assert await client.sbom_for_scan("scan-does-not-exist") is None


async def test_5xx_raises_a_typed_error() -> None:
    client = _client(responding(500, {"error": "cluster_block_exception"}))
    with pytest.raises(UpstreamResponseError) as exc_info:
        await client.sbom_for_scan("scan-42")
    assert exc_info.value.status_code == 500


async def test_timeout_raises_a_typed_error() -> None:
    client = _client(raising(lambda request: httpx.ReadTimeout("simulated", request=request)))
    with pytest.raises(UpstreamTimeout):
        await client.sbom_for_scan("scan-42")


async def test_connection_failure_raises_a_typed_error() -> None:
    client = _client(raising(lambda request: httpx.ConnectError("simulated", request=request)))
    with pytest.raises(UpstreamUnavailable):
        await client.sbom_for_scan("scan-42")


async def test_no_secret_appears_in_exception_or_logs_on_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport, seen = capturing(500, {"error": "internal"})
    client = _client(transport)

    with caplog.at_level("DEBUG"), pytest.raises(UpstreamResponseError) as exc_info:
        await client.sbom_for_scan("scan-42")

    assert seen[0]["authorization"] == f"Bearer {_SECRET}"

    assert _SECRET not in str(exc_info.value)
    assert _SECRET not in repr(exc_info.value)
    assert _SECRET not in caplog.text
