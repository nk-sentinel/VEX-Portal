"""Tests for the evidence collection service (``app/services/collection.py``).

The happy-path test round-trips over real HTTP against all three live fakes
(``fakes/iq``, ``fakes/jfrog``, ``fakes/bitbucket``) and checks the pack
matches the sample scenario's three documented cases (see
``fakes/README.md``). The collector-failure test uses a stub ``IqClient``
so the failure injection is deterministic rather than relying on a live fake
producing a failure on purpose.
"""

from __future__ import annotations

from dataclasses import replace

from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.errors import UpstreamResponseError
from app.adapters.factory import get_artifact_store, get_iq_client, get_source_repository
from app.adapters.protocols import (
    FindingRef,
    PolicyViolation,
    RawReport,
    ReportComponent,
    SourceControl,
    VulnDetail,
)
from app.config import AdapterMode, Settings
from app.evidence.pack import ComponentEvidence, EvidencePack
from app.provenance.fingerprint import FingerprintResult, Verdict
from app.repos.models import Assessment, Evidence, FindingOutcome
from app.rules.engine import RuleEngine
from app.rules.registry import ACTIVE_RULES
from app.services.collection import CollectionFailure, build_tier3_signals, collect_evidence
from tests.adapters.support import (
    BITBUCKET_BASE_URL,
    IQ_BASE_URL,
    JFROG_BASE_URL,
    require_reachable,
)
from tests.artifact.factories import make_class_file, make_spring_boot_jar

APP_ID = "4f6d8a2c9b1e4a7f8c3d2b1a0f9e8d7c"
REPORT_ID = "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
COORDINATES = "libs-release-local/com/example/payments-api/1.0.0/payments-api-1.0.0.jar"


class _StubSourceRepository:
    async def search_symbol(self, repo: str, symbol: str, ref: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def file(self, repo: str, path: str, ref: str):  # pragma: no cover - unused
        raise NotImplementedError


class _BrokenVulnerabilityIq:
    """A real report/artifact-adjacent shape, but ``vulnerability`` always
    fails — used to prove a per-CVE collector failure makes that finding
    inconclusive rather than clear, without depending on a live fake
    producing a failure on purpose.
    """

    def __init__(self, report: RawReport) -> None:
        self._report = report

    async def applications_for_user(self, user_token: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def report(self, application_id: str, report_id: str) -> RawReport:
        return self._report

    async def vulnerability(self, vuln_id: str, component_purl: str | None):
        raise UpstreamResponseError("GET", f"/api/v2/vulnerabilities/{vuln_id}", 503)

    async def remediation(self, application_id: str, purl: str):
        return None

    async def source_control(self, application_id: str) -> SourceControl | None:
        return None

    async def create_determination(self, finding: FindingRef, options):  # pragma: no cover
        raise NotImplementedError

    async def revoke_determination(self, link_id: str) -> None:  # pragma: no cover
        raise NotImplementedError


class _StubArtifactStore:
    def __init__(self, data: bytes) -> None:
        self._data = data

    async def fetch(self, coordinates: str) -> bytes:
        return self._data

    async def build_info(self, coordinates: str):  # pragma: no cover - unused
        raise NotImplementedError


async def test_collect_evidence_round_trips_against_live_fakes(session: AsyncSession) -> None:
    require_reachable(IQ_BASE_URL)
    require_reachable(JFROG_BASE_URL)
    require_reachable(BITBUCKET_BASE_URL)

    settings = Settings(
        adapter_mode=AdapterMode.FAKE,
        iq_service_user="svc",
        iq_service_token=SecretStr("iq-tok"),
        jfrog_token=SecretStr("jfrog-tok"),
        bitbucket_token=SecretStr("bitbucket-tok"),
    )
    iq = get_iq_client(settings)
    artifact_store = get_artifact_store(settings)
    source_repository = get_source_repository(settings)

    assessment = Assessment(application_id=APP_ID, report_id=REPORT_ID, requester="test")
    session.add(assessment)
    await session.flush()

    result = await collect_evidence(
        APP_ID,
        REPORT_ID,
        COORDINATES,
        assessment_id=assessment.id,
        iq=iq,
        artifact_store=artifact_store,
        source_repository=source_repository,
        session=session,
    )
    await session.commit()

    assert result.failures == ()
    assert {c.cve for c in result.pack.components} == {
        "CVE-2022-42889",
        "CVE-2021-44228",
        "CVE-2015-6420",
    }

    by_cve = {c.cve: c for c in result.pack.components}
    # CVE-2022-42889: clearly affected — ships and is referenced.
    assert by_cve["CVE-2022-42889"].class_present is True
    assert by_cve["CVE-2022-42889"].referenced is True

    # CVE-2021-44228: ships, not directly referenced, but a reflection
    # escape hatch elsewhere makes that "not referenced" untrustworthy.
    assert by_cve["CVE-2021-44228"].class_present is True
    assert by_cve["CVE-2021-44228"].reference_scan_conclusive is False

    # CVE-2015-6420: clearly not affected — the class never ships.
    assert by_cve["CVE-2015-6420"].class_present is False

    assert result.tier3_signals["CVE-2022-42889"].kev is True
    assert result.tier3_signals["CVE-2021-44228"].epss is not None
    assert result.tier3_signals["CVE-2021-44228"].epss >= 0.9
    # commons-collections (CVE-2015-6420) has no fix available.
    assert result.tier3_signals["CVE-2015-6420"].fix_available is False
    # commons-text (CVE-2022-42889) does have a fix available.
    assert result.tier3_signals["CVE-2022-42889"].fix_available is True

    assert result.source_control is not None
    assert result.symbol_hits.get("CVE-2022-42889")

    rows = (await session.execute(select(Assessment))).scalars().all()
    assert len(rows) == 1

    evidence_rows = (await session.execute(select(Evidence))).scalars().all()
    assert len(evidence_rows) > 5
    assert {row.assessment_id for row in evidence_rows} == {assessment.id}


async def test_collector_failure_makes_the_finding_inconclusive_not_clear(
    session: AsyncSession,
) -> None:
    artifact = make_spring_boot_jar(
        app_classes={"com/example/App.class": make_class_file(["java/lang/String"])},
        libraries={},
    )
    report = RawReport(
        components=[ReportComponent(purl="pkg:maven/x/y@1.0?type=jar", sha1="deadbeef")],
        violations=[
            PolicyViolation(
                cve="CVE-9999-0001",
                purl="pkg:maven/x/y@1.0?type=jar",
                policy_id="p1",
                violation_id="v1",
                threat_level=5,
            )
        ],
        scan_id=REPORT_ID,
        commit_sha=None,
        branch=None,
    )
    iq = _BrokenVulnerabilityIq(report)
    artifact_store = _StubArtifactStore(artifact)
    source_repository = _StubSourceRepository()

    assessment = Assessment(application_id=APP_ID, report_id=REPORT_ID, requester="test")
    session.add(assessment)
    await session.flush()

    result = await collect_evidence(
        APP_ID,
        REPORT_ID,
        COORDINATES,
        assessment_id=assessment.id,
        iq=iq,
        artifact_store=artifact_store,
        source_repository=source_repository,
        session=session,
    )

    assert len(result.failures) == 1
    failure = result.failures[0]
    assert isinstance(failure, CollectionFailure)
    assert failure.cve == "CVE-9999-0001"

    component = next(c for c in result.pack.components if c.cve == "CVE-9999-0001")
    assert component.class_paths == []

    outcome = RuleEngine(ACTIVE_RULES).evaluate_component(result.pack, component)
    assert outcome.proposed is FindingOutcome.NEEDS_REVIEW


def test_build_tier3_signals_passes_kev_through_unchanged() -> None:
    """The pure combination step, tested directly: this is what
    ``test_unknown_kev_survives_into_the_signals_and_blocks_a_clear`` below
    depends on staying true — kev must never be substituted with a guessed
    default, in either direction."""
    absent = VulnDetail(
        cve="CVE-2024-0001",
        cvss_vector=None,
        cvss_score=None,
        epss_score=None,
        is_kev=None,
        cwe_ids=[],
        affected_version_range=None,
        root_causes=[],
    )
    confirmed_false = replace(absent, is_kev=False)
    confirmed_true = replace(absent, is_kev=True)

    assert build_tier3_signals(absent, None).kev is None
    assert build_tier3_signals(confirmed_false, None).kev is False
    assert build_tier3_signals(confirmed_true, None).kev is True


def test_unknown_kev_survives_into_the_signals_and_blocks_a_clear() -> None:
    """The whole point of fix round 1: an absent kevData block must reach
    the rule engine as an unresolved blocker, not be erased anywhere along
    build_tier3_signals -> RuleEngine.evaluate_component. Without this fix,
    this exact scenario — Tier 1 proof present, KEV status never
    established — would have auto-cleared the finding.
    """
    vuln_with_unknown_kev = VulnDetail(
        cve="CVE-2024-0001",
        cvss_vector=None,
        cvss_score=None,
        epss_score=0.01,
        is_kev=None,
        cwe_ids=[],
        affected_version_range=None,
        root_causes=["com/example/Vulnerable.class"],
    )

    signals = build_tier3_signals(vuln_with_unknown_kev, None)
    assert signals.kev is None

    pack = EvidencePack(
        provenance=FingerprintResult(
            verdict=Verdict.MATCH,
            matched=7,
            report_total=7,
            unmatched_report_hashes=[],
            unmatched_artifact_hashes=[],
            surplus_ratio=0.0,
            ratio=1.0,
        )
    )
    component = ComponentEvidence(
        cve="CVE-2024-0001",
        class_paths=["com/example/Vulnerable.class"],
        # class_present=False alone would let t1-class-absent clear this at
        # tier PROOF with no further evidence needed.
        class_present=False,
        referenced=False,
        reference_scan_conclusive=True,
    )

    outcome = RuleEngine(ACTIVE_RULES).evaluate_component(pack, component, signals)

    assert outcome.proposed is FindingOutcome.NEEDS_REVIEW
    assert "kev" in outcome.blocked_by
