"""Tests for the admission service (``app/services/admission.py``).

Most cases use stub ``IqClient``/``ArtifactStore`` implementations so each
failure path is exercised in isolation without a live fake. One round trip
against the live fakes (``fakes/iq`` + ``fakes/jfrog``) proves the whole
chain — real HTTP, real archive parsing, real provenance compare — actually
agrees with the unit-level behaviour, mirroring how ``tests/adapters/``
mixes live-fake round trips with synthetic failure injection.
"""

from __future__ import annotations

import hashlib

import pytest
from pydantic import SecretStr

from app.adapters.errors import UpstreamResponseError, UpstreamUnavailable
from app.adapters.factory import get_artifact_store, get_iq_client
from app.adapters.iq.client import IqHttpClient
from app.adapters.jfrog.client import JFrogHttpClient
from app.adapters.protocols import RawReport, ReportComponent
from app.config import AdapterMode, Settings
from app.provenance.fingerprint import Verdict
from app.services.admission import (
    AdmittedRequest,
    ArtifactUnavailable,
    ProvenanceMismatch,
    ReportUnavailable,
    admit,
)
from tests.adapters.support import IQ_BASE_URL, JFROG_BASE_URL, require_reachable
from tests.artifact.factories import make_class_file, make_jar, make_spring_boot_jar

APP_ID = "4f6d8a2c9b1e4a7f8c3d2b1a0f9e8d7c"
REPORT_ID = "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
COORDINATES = "libs-release-local/com/example/payments-api/1.0.0/payments-api-1.0.0.jar"


class _StubIq:
    """A minimal, Protocol-conforming IqClient — only ``report`` is ever
    exercised by admission, so every other method is a deliberate stub."""

    def __init__(self, *, report: RawReport | None = None, error: Exception | None = None):
        self._report = report
        self._error = error

    async def applications_for_user(self, user_token: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def report(self, application_id: str, report_id: str) -> RawReport:
        if self._error is not None:
            raise self._error
        assert self._report is not None
        return self._report

    async def vulnerability(self, vuln_id: str, component_purl: str | None):  # pragma: no cover
        raise NotImplementedError

    async def remediation(self, application_id: str, purl: str):  # pragma: no cover
        raise NotImplementedError

    async def source_control(self, application_id: str):  # pragma: no cover
        raise NotImplementedError

    async def create_determination(self, finding, options):  # pragma: no cover
        raise NotImplementedError

    async def revoke_determination(self, link_id: str) -> None:  # pragma: no cover
        raise NotImplementedError


class _StubArtifactStore:
    """A minimal, Protocol-conforming ArtifactStore — only ``fetch`` is ever
    exercised by admission."""

    def __init__(self, *, data: bytes | None = None, error: Exception | None = None):
        self._data = data
        self._error = error

    async def fetch(self, coordinates: str) -> bytes:
        if self._error is not None:
            raise self._error
        assert self._data is not None
        return self._data

    async def build_info(self, coordinates: str):  # pragma: no cover - unused
        raise NotImplementedError


def _matching_artifact_and_report() -> tuple[bytes, RawReport]:
    """A minimal artifact whose bundled library hashes are exactly what the
    report lists — a genuine MATCH, needing enough components to clear
    ``compare``'s minimum-components floor.
    """
    libraries = {f"lib-{i}.jar": make_jar({f"pkg/C{i}.class": bytes([i])}) for i in range(6)}
    artifact = make_spring_boot_jar(
        app_classes={"com/example/App.class": make_class_file(["java/lang/String"])},
        libraries=libraries,
    )
    report_hashes = {hashlib.sha1(payload).hexdigest() for payload in libraries.values()}
    components = [
        ReportComponent(purl=f"pkg:generic/lib-{i}", sha1=h) for i, h in enumerate(report_hashes)
    ]
    report = RawReport(
        components=components,
        violations=[],
        scan_id=REPORT_ID,
        commit_sha=None,
        branch=None,
    )
    return artifact, report


async def test_admit_succeeds_when_the_artifact_matches_the_report() -> None:
    artifact, report = _matching_artifact_and_report()
    iq = _StubIq(report=report)
    store = _StubArtifactStore(data=artifact)

    result = await admit(APP_ID, REPORT_ID, COORDINATES, iq=iq, artifact_store=store)

    assert isinstance(result, AdmittedRequest)
    assert result.fingerprint.verdict is Verdict.MATCH
    assert result.report is report
    assert result.artifact == artifact


async def test_report_unavailable_raises_with_an_actionable_message() -> None:
    iq = _StubIq(error=UpstreamResponseError("GET", "/reports/x", 404))
    store = _StubArtifactStore(data=b"unused")

    with pytest.raises(ReportUnavailable, match="report still exists"):
        await admit(APP_ID, REPORT_ID, COORDINATES, iq=iq, artifact_store=store)


async def test_artifact_unavailable_when_fetch_fails() -> None:
    _, report = _matching_artifact_and_report()
    iq = _StubIq(report=report)
    store = _StubArtifactStore(error=UpstreamUnavailable("connection refused"))

    with pytest.raises(ArtifactUnavailable, match="could not be retrieved from JFrog"):
        await admit(APP_ID, REPORT_ID, COORDINATES, iq=iq, artifact_store=store)


async def test_artifact_unavailable_when_bytes_are_not_a_readable_archive() -> None:
    _, report = _matching_artifact_and_report()
    iq = _StubIq(report=report)
    store = _StubArtifactStore(data=b"not a zip file at all")

    with pytest.raises(ArtifactUnavailable, match="could not be read as a JAR/WAR archive"):
        await admit(APP_ID, REPORT_ID, COORDINATES, iq=iq, artifact_store=store)


async def test_provenance_mismatch_blocks_admission() -> None:
    artifact, _ = _matching_artifact_and_report()
    unrelated_hashes = {hashlib.sha1(f"unrelated-{i}".encode()).hexdigest() for i in range(6)}
    mismatched_report = RawReport(
        components=[ReportComponent(purl="pkg:generic/x", sha1=h) for h in unrelated_hashes],
        violations=[],
        scan_id=REPORT_ID,
        commit_sha=None,
        branch=None,
    )
    iq = _StubIq(report=mismatched_report)
    store = _StubArtifactStore(data=artifact)

    with pytest.raises(ProvenanceMismatch, match="does not match report"):
        await admit(APP_ID, REPORT_ID, COORDINATES, iq=iq, artifact_store=store)


async def test_provenance_insufficient_data_is_not_treated_as_a_pass() -> None:
    """Fewer report components than the fingerprint's minimum floor yields
    INSUFFICIENT_DATA, not MATCH — and INSUFFICIENT_DATA must still refuse
    admission, per app/provenance/fingerprint.py's own docstring: too little
    data to assert a match is provenance unproven, not provenance confirmed.
    """
    artifact, _ = _matching_artifact_and_report()
    few_hashes = {hashlib.sha1(f"only-{i}".encode()).hexdigest() for i in range(2)}
    sparse_report = RawReport(
        components=[ReportComponent(purl="pkg:generic/x", sha1=h) for h in few_hashes],
        violations=[],
        scan_id=REPORT_ID,
        commit_sha=None,
        branch=None,
    )
    iq = _StubIq(report=sparse_report)
    store = _StubArtifactStore(data=artifact)

    with pytest.raises(ProvenanceMismatch, match="insufficient_data"):
        await admit(APP_ID, REPORT_ID, COORDINATES, iq=iq, artifact_store=store)


async def test_failure_messages_differ_across_the_three_checks() -> None:
    artifact, report = _matching_artifact_and_report()
    unrelated_hashes = {hashlib.sha1(f"unrelated-{i}".encode()).hexdigest() for i in range(6)}
    mismatched_report = RawReport(
        components=[ReportComponent(purl="pkg:generic/x", sha1=h) for h in unrelated_hashes],
        violations=[],
        scan_id=REPORT_ID,
        commit_sha=None,
        branch=None,
    )

    messages: list[str] = []
    for iq, store in (
        (_StubIq(error=UpstreamResponseError("GET", "/x", 404)), _StubArtifactStore(data=b"x")),
        (_StubIq(report=report), _StubArtifactStore(error=UpstreamUnavailable("refused"))),
        (_StubIq(report=mismatched_report), _StubArtifactStore(data=artifact)),
    ):
        with pytest.raises(Exception) as exc_info:  # noqa: PT011 - deliberately heterogeneous
            await admit(APP_ID, REPORT_ID, COORDINATES, iq=iq, artifact_store=store)
        messages.append(str(exc_info.value))

    assert len(set(messages)) == len(messages)


async def test_admit_round_trips_against_live_fakes() -> None:
    """The full chain, over real HTTP: fake IQ's report, fake JFrog's
    artifact, real archive parsing, real provenance compare — matching
    fakes/README.md's documented guarantee that the sample artifact's
    library hashes exactly match the sample report's component hashes.
    """
    require_reachable(IQ_BASE_URL)
    require_reachable(JFROG_BASE_URL)

    settings = Settings(
        adapter_mode=AdapterMode.FAKE,
        iq_service_user="svc",
        iq_service_token=SecretStr("iq-tok"),
        jfrog_token=SecretStr("jfrog-tok"),
    )
    iq: IqHttpClient = get_iq_client(settings)  # type: ignore[assignment]
    store: JFrogHttpClient = get_artifact_store(settings)  # type: ignore[assignment]
    try:
        result = await admit(APP_ID, REPORT_ID, COORDINATES, iq=iq, artifact_store=store)
    finally:
        await iq.aclose()
        await store.aclose()

    assert result.fingerprint.verdict is Verdict.MATCH
    assert len(result.report.components) == 7
