"""Structural conformance of adapter Protocols.

These Protocols (``app.adapters.protocols``) are the only shape any
external-system client may present to the rest of the portal. The risk this
suite guards against is drift: a fake implementation (built in a later task,
against recorded fixtures) and a real implementation (built against the
vendor's actual API) only stay interchangeable if both are independently
checked against the same contract. Two hand-written stand-ins are used per
Protocol here — one shaped like a fake, one shaped like a real client — so
this test exercises the same class of drift a genuine fake/real pair would
hit, without depending on tasks 7 and 8 having run yet.

Each positive case is paired with a negative one: a double deliberately
missing one required method must NOT satisfy the Protocol. A bare "both
doubles satisfy it" assertion would pass even if ``runtime_checkable`` were
checking nothing at all; the negative case is what proves the check actually
discriminates — this project has shipped non-discriminating tests before.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.adapters.protocols import (
    Adjudicator,
    AiVerdictDto,
    Application,
    ArtifactStore,
    BuildInfo,
    DeterminationOptions,
    FindingRef,
    IqClient,
    PolicyViolation,
    RawReport,
    Remediation,
    ReportComponent,
    ScanArchive,
    ScanRecord,
    SourceControl,
    SourceRepository,
    SymbolHit,
    VulnDetail,
)
from app.domain.determination import Confidence, Justification, State
from app.evidence.pack import EvidencePack

_EXPIRES = datetime(2026, 9, 8, tzinfo=UTC)


# ---------------------------------------------------------------------------
# IqClient
# ---------------------------------------------------------------------------


class _FakeIqClient:
    """Stands in for the in-memory, fixture-backed client task 7/8 will build."""

    async def applications_for_user(self, user_token: str) -> list[Application]:
        return [Application(id="app-1", name="demo")]

    async def report(self, application_id: str, report_id: str) -> RawReport:
        return RawReport(
            components=[ReportComponent(purl="pkg:maven/x/y@1.0", sha1="a" * 40)],
            violations=[
                PolicyViolation(
                    cve="CVE-2022-42889",
                    purl="pkg:maven/x/y@1.0",
                    policy_id="pol-1",
                    violation_id="vio-1",
                    threat_level=8,
                )
            ],
            scan_id="scan-1",
            commit_sha="deadbeef",
            branch="main",
        )

    async def vulnerability(self, vuln_id: str, component_purl: str | None) -> VulnDetail:
        return VulnDetail(
            cve=vuln_id,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
            epss_score=0.42,
            is_kev=False,
            cwe_ids=["CWE-502"],
            affected_version_range="[1.0.0,1.9.0)",
            root_causes=["org/apache/commons/text/StringSubstitutor.class"],
        )

    async def remediation(self, application_id: str, purl: str) -> Remediation | None:
        return Remediation(fix_version="1.10.0", is_transitive=False)

    async def source_control(self, application_id: str) -> SourceControl | None:
        return SourceControl(repository_url="https://bitbucket.example/scm/app", base_branch="main")

    async def create_determination(self, finding: FindingRef, options: DeterminationOptions) -> str:
        return "link-1"

    async def revoke_determination(self, link_id: str) -> None:
        return None


class _RealIqClient:
    """Stands in for the httpx-backed client task 8 will build.

    Written independently of ``_FakeIqClient`` above — same method names and
    signatures, different bodies — so that if the Protocol drifts, both need
    fixing rather than one implementation silently defining what "conforms"
    means.
    """

    async def applications_for_user(self, user_token: str) -> list[Application]:
        raise NotImplementedError

    async def report(self, application_id: str, report_id: str) -> RawReport:
        raise NotImplementedError

    async def vulnerability(self, vuln_id: str, component_purl: str | None) -> VulnDetail:
        raise NotImplementedError

    async def remediation(self, application_id: str, purl: str) -> Remediation | None:
        raise NotImplementedError

    async def source_control(self, application_id: str) -> SourceControl | None:
        raise NotImplementedError

    async def create_determination(self, finding: FindingRef, options: DeterminationOptions) -> str:
        raise NotImplementedError

    async def revoke_determination(self, link_id: str) -> None:
        raise NotImplementedError


class _IqClientMissingRevoke:
    """Everything IqClient needs except ``revoke_determination``."""

    async def applications_for_user(self, user_token: str) -> list[Application]:
        return []

    async def report(self, application_id: str, report_id: str) -> RawReport:
        raise NotImplementedError

    async def vulnerability(self, vuln_id: str, component_purl: str | None) -> VulnDetail:
        raise NotImplementedError

    async def remediation(self, application_id: str, purl: str) -> Remediation | None:
        raise NotImplementedError

    async def source_control(self, application_id: str) -> SourceControl | None:
        raise NotImplementedError

    async def create_determination(self, finding: FindingRef, options: DeterminationOptions) -> str:
        raise NotImplementedError


def test_iq_client_satisfied_by_independent_fake_and_real_style_implementations() -> None:
    fake: IqClient = _FakeIqClient()
    real: IqClient = _RealIqClient()
    assert isinstance(fake, IqClient)
    assert isinstance(real, IqClient)


def test_iq_client_rejects_an_implementation_missing_a_method() -> None:
    assert not isinstance(_IqClientMissingRevoke(), IqClient)


# ---------------------------------------------------------------------------
# ArtifactStore
# ---------------------------------------------------------------------------


class _FakeArtifactStore:
    async def fetch(self, coordinates: str) -> bytes:
        return b"PK\x03\x04"

    async def build_info(self, coordinates: str) -> BuildInfo | None:
        return BuildInfo(
            repository_url="https://bitbucket.example/scm/app",
            commit_sha="deadbeef",
            branch="main",
        )


class _RealArtifactStore:
    async def fetch(self, coordinates: str) -> bytes:
        raise NotImplementedError

    async def build_info(self, coordinates: str) -> BuildInfo | None:
        raise NotImplementedError


class _ArtifactStoreMissingBuildInfo:
    async def fetch(self, coordinates: str) -> bytes:
        return b""


def test_artifact_store_satisfied_by_independent_fake_and_real_style_implementations() -> None:
    fake: ArtifactStore = _FakeArtifactStore()
    real: ArtifactStore = _RealArtifactStore()
    assert isinstance(fake, ArtifactStore)
    assert isinstance(real, ArtifactStore)


def test_artifact_store_rejects_an_implementation_missing_a_method() -> None:
    assert not isinstance(_ArtifactStoreMissingBuildInfo(), ArtifactStore)


# ---------------------------------------------------------------------------
# SourceRepository
# ---------------------------------------------------------------------------


class _FakeSourceRepository:
    async def search_symbol(self, repo: str, symbol: str, ref: str) -> list[SymbolHit]:
        return [SymbolHit(path="src/App.java", line=42, snippet="new StringSubstitutor()")]

    async def file(self, repo: str, path: str, ref: str) -> bytes | None:
        return b"class App {}"


class _RealSourceRepository:
    async def search_symbol(self, repo: str, symbol: str, ref: str) -> list[SymbolHit]:
        raise NotImplementedError

    async def file(self, repo: str, path: str, ref: str) -> bytes | None:
        raise NotImplementedError


class _SourceRepositoryMissingFile:
    async def search_symbol(self, repo: str, symbol: str, ref: str) -> list[SymbolHit]:
        return []


def test_source_repository_satisfied_by_independent_fake_and_real_style_implementations() -> None:
    fake: SourceRepository = _FakeSourceRepository()
    real: SourceRepository = _RealSourceRepository()
    assert isinstance(fake, SourceRepository)
    assert isinstance(real, SourceRepository)


def test_source_repository_rejects_an_implementation_missing_a_method() -> None:
    assert not isinstance(_SourceRepositoryMissingFile(), SourceRepository)


# ---------------------------------------------------------------------------
# Adjudicator
# ---------------------------------------------------------------------------


class _FakeAdjudicator:
    async def adjudicate(self, pack: EvidencePack, finding: FindingRef) -> AiVerdictDto:
        return AiVerdictDto(
            state=State.UNDER_INVESTIGATION,
            justification=None,
            confidence=Confidence.INSUFFICIENT,
            evidence_refs=[],
            missing_evidence=["source_symbol_search"],
        )


class _RealAdjudicator:
    async def adjudicate(self, pack: EvidencePack, finding: FindingRef) -> AiVerdictDto:
        raise NotImplementedError


class _AdjudicatorMissingMethod:
    pass


def test_adjudicator_satisfied_by_independent_fake_and_real_style_implementations() -> None:
    fake: Adjudicator = _FakeAdjudicator()
    real: Adjudicator = _RealAdjudicator()
    assert isinstance(fake, Adjudicator)
    assert isinstance(real, Adjudicator)


def test_adjudicator_rejects_an_implementation_missing_a_method() -> None:
    assert not isinstance(_AdjudicatorMissingMethod(), Adjudicator)


def test_adjudicator_output_can_abstain() -> None:
    """Without this the 'unsure' bucket stays silently empty (CLAUDE.md rule 3)."""
    verdict = AiVerdictDto(
        state=State.UNDER_INVESTIGATION,
        justification=None,
        confidence=Confidence.INSUFFICIENT,
        evidence_refs=[],
        missing_evidence=["reachability"],
    )
    assert verdict.confidence is Confidence.INSUFFICIENT
    assert verdict.confidence.abstains()


# ---------------------------------------------------------------------------
# ScanArchive
# ---------------------------------------------------------------------------


class _FakeScanArchive:
    async def sbom_for_scan(self, scan_id: str) -> ScanRecord | None:
        return ScanRecord(
            scan_id=scan_id,
            components=[ReportComponent(purl="pkg:maven/x/y@1.0", sha1="a" * 40)],
            cve_ids=["CVE-2022-42889"],
        )


class _RealScanArchive:
    async def sbom_for_scan(self, scan_id: str) -> ScanRecord | None:
        raise NotImplementedError


class _ScanArchiveMissingMethod:
    pass


def test_scan_archive_satisfied_by_independent_fake_and_real_style_implementations() -> None:
    fake: ScanArchive = _FakeScanArchive()
    real: ScanArchive = _RealScanArchive()
    assert isinstance(fake, ScanArchive)
    assert isinstance(real, ScanArchive)


def test_scan_archive_rejects_an_implementation_missing_a_method() -> None:
    assert not isinstance(_ScanArchiveMissingMethod(), ScanArchive)


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

# The vocabulary rule (docs/naming.md; the one exception is app/adapters/iq/)
# is verified by grep as part of this task's own checks, not by a pytest test
# here — a test asserting the term's absence would need to write the term
# itself somewhere in this file (an identifier or a docstring) to describe
# what it checks, which would violate the rule it is trying to enforce.


def test_determination_options_carries_expiry_not_open_ended() -> None:
    """CLAUDE.md rule 4: determinations expire at 7 days and are never auto-renewed."""
    options = DeterminationOptions(
        justification=Justification.CODE_NOT_PRESENT,
        assessment_id="assess-1",
        rationale="Vulnerable class absent from the shipped artifact.",
        expires_at=_EXPIRES,
    )
    assert options.expires_at == _EXPIRES
