"""Tests for the real JFrog Artifactory client (``app/adapters/jfrog/client.py``).

Happy-path cases round-trip over real HTTP against ``fakes/jfrog``. The
absence of build info and the failure-taxonomy cases use
``httpx.MockTransport`` — the live fake's sample scenario always has build
info attached to its one artifact, and cannot 500/hang/refuse on purpose.
"""

from __future__ import annotations

import httpx
import pytest

from app.adapters.errors import UpstreamResponseError, UpstreamTimeout, UpstreamUnavailable
from app.adapters.jfrog.client import JFrogHttpClient
from app.adapters.protocols import ArtifactStore
from tests.adapters.support import JFROG_BASE_URL, capturing, raising, require_reachable, responding

COORDINATES = "libs-release-local/com/example/payments-api/1.0.0/payments-api-1.0.0.jar"
_SECRET = "jfrog-token-4e5d6c7b8a9f0e1d2c3b"


@pytest.fixture
def client() -> JFrogHttpClient:
    require_reachable(JFROG_BASE_URL)
    return JFrogHttpClient(base_url=JFROG_BASE_URL, token=_SECRET)


def test_jfrog_http_client_satisfies_the_protocol(client: JFrogHttpClient) -> None:
    assert isinstance(client, ArtifactStore)


async def test_fetch_returns_the_real_artifact_bytes(client: JFrogHttpClient) -> None:
    data = await client.fetch(COORDINATES)
    assert data[:4] == b"PK\x03\x04"  # a real zip, not a stub
    assert len(data) > 1000


async def test_fetch_empty_coordinates_404s_as_an_error(client: JFrogHttpClient) -> None:
    """The caller named these coordinates — an artifact that is not there is
    something to raise about, not shrug off as an absence."""
    with pytest.raises(UpstreamResponseError) as exc_info:
        await client.fetch("")
    assert exc_info.value.status_code == 404


async def test_build_info_round_trips_repository_commit_and_branch(client: JFrogHttpClient) -> None:
    build_info = await client.build_info(COORDINATES)
    assert build_info is not None
    assert build_info.repository_url == "https://bitbucket.example.internal/scm/pay/payments-api.git"
    assert build_info.commit_sha == "521d1b3b25ba930e3a8745189e14926e117a3270"
    assert build_info.branch == "release/2026.09"


async def test_build_info_absent_properties_is_a_typed_absence() -> None:
    """An artifact that was never deployed with build info attached — CI not
    publishing Build Info is a real, open item (docs/design.md)."""
    transport = responding(200, {"uri": "/api/storage/x", "properties": {}})
    client = JFrogHttpClient(base_url=JFROG_BASE_URL, token=_SECRET, transport=transport)
    assert await client.build_info("some/path.jar") is None


async def test_build_info_404_properties_is_a_typed_absence() -> None:
    transport = responding(404, {"detail": "not found"})
    client = JFrogHttpClient(base_url=JFROG_BASE_URL, token=_SECRET, transport=transport)
    assert await client.build_info("some/path.jar") is None


async def test_5xx_raises_a_typed_error() -> None:
    transport = responding(503, {"error": "unavailable"})
    client = JFrogHttpClient(base_url=JFROG_BASE_URL, token=_SECRET, transport=transport)
    with pytest.raises(UpstreamResponseError) as exc_info:
        await client.fetch(COORDINATES)
    assert exc_info.value.status_code == 503


async def test_timeout_raises_a_typed_error() -> None:
    transport = raising(lambda request: httpx.ReadTimeout("simulated", request=request))
    client = JFrogHttpClient(base_url=JFROG_BASE_URL, token=_SECRET, transport=transport)
    with pytest.raises(UpstreamTimeout):
        await client.fetch(COORDINATES)


async def test_connection_failure_raises_a_typed_error() -> None:
    transport = raising(lambda request: httpx.ConnectError("simulated", request=request))
    client = JFrogHttpClient(base_url=JFROG_BASE_URL, token=_SECRET, transport=transport)
    with pytest.raises(UpstreamUnavailable):
        await client.fetch(COORDINATES)


async def test_no_secret_appears_in_exception_or_logs_on_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport, seen = capturing(500, {"error": "internal"})
    client = JFrogHttpClient(base_url=JFROG_BASE_URL, token=_SECRET, transport=transport)

    with caplog.at_level("DEBUG"), pytest.raises(UpstreamResponseError) as exc_info:
        await client.fetch(COORDINATES)

    # Discriminating: the token really was sent as a bearer header.
    assert seen[0]["authorization"] == f"Bearer {_SECRET}"

    assert _SECRET not in str(exc_info.value)
    assert _SECRET not in repr(exc_info.value)
    assert _SECRET not in caplog.text
