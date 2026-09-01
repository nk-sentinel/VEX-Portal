"""Tests for the real Nexus IQ client (``app/adapters/iq/client.py``).

Happy-path and typed-absence cases round-trip over real HTTP against
``fakes/iq`` (``docker compose up -d vex-fake-iq``, matching
``app/config.py``'s ``fake_iq_url`` default). The failure-taxonomy cases a
running fake cannot produce on purpose — a 500, a timeout, a connection
failure — use ``httpx.MockTransport`` against the same real client class
(see ``tests/adapters/support.py``).
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import httpx
import pytest

from app.adapters.errors import UpstreamResponseError, UpstreamTimeout, UpstreamUnavailable
from app.adapters.iq.client import IqHttpClient, ViolationNotFound
from app.adapters.protocols import DeterminationOptions, FindingRef, IqClient
from app.domain.determination import Justification
from tests.adapters.support import IQ_BASE_URL, capturing, raising, require_reachable, responding

APP_ID = "4f6d8a2c9b1e4a7f8c3d2b1a0f9e8d7c"
REPORT_ID = "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
_SECRET = "sekrit-service-token-9f8a7c6b5d4e"


@pytest.fixture
def client() -> IqHttpClient:
    require_reachable(IQ_BASE_URL)
    return IqHttpClient(base_url=IQ_BASE_URL, service_user="svc", service_token=_SECRET)


def test_iq_http_client_satisfies_the_protocol(client: IqHttpClient) -> None:
    assert isinstance(client, IqClient)


async def test_applications_for_user_round_trips(client: IqHttpClient) -> None:
    apps = await client.applications_for_user("some-user-token")
    assert len(apps) == 1
    assert apps[0].id == APP_ID
    assert apps[0].name == "Payments API"


async def test_applications_for_user_authenticates_as_the_user_not_the_service() -> None:
    """``Application``'s docstring: entitlement is the user's own IQ-token-
    scoped list, not the service credential — so this one call must send the
    user's token, not the client's default Basic auth.
    """
    transport, seen = capturing(200, {"applications": []})
    client = IqHttpClient(
        base_url=IQ_BASE_URL,
        service_user="svc",
        service_token=_SECRET,
        transport=transport,
    )
    await client.applications_for_user("user-owned-token")
    assert seen[0]["Authorization"] == "Bearer user-owned-token"


async def test_report_round_trips_components_and_violations(client: IqHttpClient) -> None:
    report = await client.report(APP_ID, REPORT_ID)
    assert len(report.components) == 7
    assert {c.cve for c in report.violations} == {
        "CVE-2022-42889",
        "CVE-2021-44228",
        "CVE-2015-6420",
    }
    assert report.scan_id == REPORT_ID
    text_violation = next(v for v in report.violations if v.cve == "CVE-2022-42889")
    assert text_violation.purl == "pkg:maven/org.apache.commons/commons-text@1.9?type=jar"
    assert isinstance(text_violation.threat_level, int)


async def test_report_404_for_unknown_report_id_is_an_error(client: IqHttpClient) -> None:
    """The caller named this report id — a 404 here is not "no report", it is
    a bug or a purged report the caller must be told about."""
    with pytest.raises(UpstreamResponseError) as exc_info:
        await client.report(APP_ID, "does-not-exist")
    assert exc_info.value.status_code == 404


async def test_vulnerability_round_trips_kev_epss_and_cvss(client: IqHttpClient) -> None:
    vuln = await client.vulnerability("CVE-2022-42889", None)
    assert vuln.is_kev is True
    assert vuln.cvss_score == pytest.approx(9.8)
    assert vuln.cwe_ids == ["1321"]
    assert vuln.root_causes == ["org/apache/commons/text/StringSubstitutor.class"]


async def test_vulnerability_404_for_unknown_cve_is_an_error(client: IqHttpClient) -> None:
    with pytest.raises(UpstreamResponseError) as exc_info:
        await client.vulnerability("CVE-0000-00000", None)
    assert exc_info.value.status_code == 404


async def test_vulnerability_filters_root_causes_to_class_paths_only() -> None:
    """Design finding 2: ``rootCauses[].listOfPaths`` can carry a bare jar
    filename alongside the ``.class`` path. Not reproducible against
    ``fakes/iq`` (its sample data's ``rootCauses`` are already clean — see
    ``fakes/data/iq.json``, and asserted exactly by
    ``fakes/tests/test_fakes.py``, so this test must not depend on changing
    that fixture); exercised here with a synthetic response instead.
    """
    body = {
        "identifier": "CVE-2022-42889",
        "rootCauses": [
            {
                "listOfPaths": [
                    "commons-text-1.9.jar",
                    "org/apache/commons/text/StringSubstitutor.class",
                ],
                "versionRange": "[1.5,1.10)",
            }
        ],
    }
    client = IqHttpClient(
        base_url=IQ_BASE_URL,
        service_user="svc",
        service_token=_SECRET,
        transport=responding(200, body),
    )
    vuln = await client.vulnerability("CVE-2022-42889", None)
    assert vuln.root_causes == ["org/apache/commons/text/StringSubstitutor.class"]
    assert "commons-text-1.9.jar" not in vuln.root_causes


async def test_remediation_returns_fix_version_when_available(client: IqHttpClient) -> None:
    remediation = await client.remediation(
        APP_ID, "pkg:maven/org.apache.commons/commons-text@1.9?type=jar"
    )
    assert remediation is not None
    assert remediation.fix_version == "1.10.0"
    assert remediation.is_transitive is False


async def test_remediation_no_fix_available_is_not_a_none_result(client: IqHttpClient) -> None:
    """CLAUDE.md rule 5: no fix available is a real answer (``fix_version is
    None`` inside a ``Remediation``), never the typed absence of one."""
    remediation = await client.remediation(
        APP_ID, "pkg:maven/commons-collections/commons-collections@3.2.1?type=jar"
    )
    assert remediation is not None
    assert remediation.fix_version is None


async def test_source_control_round_trips(client: IqHttpClient) -> None:
    source_control = await client.source_control(APP_ID)
    assert source_control is not None
    assert source_control.base_branch == "release/2026.09"
    assert source_control.repository_url.startswith("https://bitbucket.example.internal/")


async def test_source_control_404_is_a_typed_absence(client: IqHttpClient) -> None:
    """A legitimately-may-not-exist 404: no source-control mapping has been
    created for this application yet."""
    assert await client.source_control("some-app-with-no-mapping") is None


async def test_create_determination_then_revoke_round_trips(client: IqHttpClient) -> None:
    finding = FindingRef(
        application_id=APP_ID,
        cve="CVE-2022-42889",
        purl="pkg:maven/org.apache.commons/commons-text@1.9?type=jar",
    )
    options = DeterminationOptions(
        justification=Justification.CODE_NOT_PRESENT,
        assessment_id="assess-round-trip",
        rationale="vulnerable class absent from the shipped artifact",
        expires_at=datetime(2026, 9, 8, tzinfo=UTC),
    )
    link_id = await client.create_determination(finding, options)
    assert link_id  # a follow-up query resolved a real id, not a placeholder

    await client.revoke_determination(link_id)
    # DELETE is idempotent: revoking an already-revoked link must not raise.
    await client.revoke_determination(link_id)


async def test_create_determination_raises_when_no_open_violation_matches(
    client: IqHttpClient,
) -> None:
    finding = FindingRef(application_id=APP_ID, cve="CVE-0000-00000", purl="pkg:maven/x/y@1.0")
    options = DeterminationOptions(
        justification=Justification.CODE_NOT_PRESENT,
        assessment_id="assess-no-match",
        rationale="n/a",
        expires_at=datetime(2026, 9, 8, tzinfo=UTC),
    )
    with pytest.raises(ViolationNotFound):
        await client.create_determination(finding, options)


async def test_5xx_raises_a_typed_error() -> None:
    client = IqHttpClient(
        base_url=IQ_BASE_URL,
        service_user="svc",
        service_token=_SECRET,
        transport=responding(500, {"error": "internal"}),
    )
    with pytest.raises(UpstreamResponseError) as exc_info:
        await client.applications_for_user("user-token")
    assert exc_info.value.status_code == 500


async def test_timeout_raises_a_typed_error() -> None:
    client = IqHttpClient(
        base_url=IQ_BASE_URL,
        service_user="svc",
        service_token=_SECRET,
        transport=raising(lambda request: httpx.ReadTimeout("simulated timeout", request=request)),
    )
    with pytest.raises(UpstreamTimeout):
        await client.applications_for_user("user-token")


async def test_connection_failure_raises_a_typed_error() -> None:
    client = IqHttpClient(
        base_url=IQ_BASE_URL,
        service_user="svc",
        service_token=_SECRET,
        transport=raising(lambda request: httpx.ConnectError("simulated refusal", request=request)),
    )
    with pytest.raises(UpstreamUnavailable):
        await client.applications_for_user("user-token")


async def test_no_secret_appears_in_exception_or_logs_on_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport, seen = capturing(500, {"error": "internal"})
    client = IqHttpClient(
        base_url=IQ_BASE_URL,
        service_user="svc",
        service_token=_SECRET,
        transport=transport,
    )
    # source_control() uses the client's default Basic auth (unlike
    # applications_for_user, which overrides to the caller's own token) —
    # this is the path that actually carries the service token.
    with caplog.at_level("DEBUG"), pytest.raises(UpstreamResponseError) as exc_info:
        await client.source_control(APP_ID)

    # Discriminating: prove the token really was sent (Basic auth
    # base64-encodes "svc:<token>"), so the "never leaked" assertions below
    # are not vacuously true against a request that never carried it.
    auth_header = seen[0]["authorization"]
    assert auth_header.startswith("Basic ")
    assert base64.b64decode(auth_header.removeprefix("Basic ")).decode() == f"svc:{_SECRET}"

    assert _SECRET not in str(exc_info.value)
    assert _SECRET not in repr(exc_info.value)
    assert _SECRET not in caplog.text
