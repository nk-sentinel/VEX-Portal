"""Tests for the determination service (``app/services/determination.py``).

Every case constructs an ``EngineOutcome`` directly rather than driving the
full ``RuleEngine`` — the engine's own tests (``tests/rules/test_engine.py``)
already prove it produces internally-consistent output; this module's job is
purely the combination/persistence/IQ-commit logic that sits one layer above
it, and the failed-``validate()`` test specifically needs an EngineOutcome
the real engine could never produce.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.iq.client import DeterminationIdUnresolved
from app.adapters.protocols import (
    AiVerdictDto,
    DeterminationOptions,
    FindingRef,
    VulnDetail,
)
from app.domain.determination import (
    Confidence,
    DeterminationError,
    EvidenceTier,
    Justification,
    State,
)
from app.evidence.pack import ComponentEvidence, EvidencePack
from app.provenance.fingerprint import FingerprintResult, Verdict
from app.repos.models import (
    Assessment,
    AuditEntry,
    Finding,
    FindingOutcome,
    IqDeterminationLink,
    RuleResult,
)
from app.rules.engine import EngineOutcome, RuleEvaluation, RuleVerdict
from app.services.determination import build_not_affected_determination, determine

PACK = EvidencePack(
    provenance=FingerprintResult(
        verdict=Verdict.MATCH,
        matched=7,
        report_total=7,
        unmatched_report_hashes=[],
        unmatched_artifact_hashes=[],
        surplus_ratio=0.0,
        ratio=1.0,
    ),
    components=[
        ComponentEvidence(
            cve="CVE-2024-0001",
            class_paths=["com/example/Vulnerable.class"],
            class_present=False,
            referenced=False,
            reference_scan_conclusive=True,
        )
    ],
)

_VULN = VulnDetail(
    cve="CVE-2024-0001",
    cvss_vector=None,
    cvss_score=None,
    epss_score=None,
    is_kev=False,
    cwe_ids=[],
    affected_version_range=None,
    root_causes=["com/example/Vulnerable.class"],
)


def _clear_verdict() -> AiVerdictDto:
    return AiVerdictDto(
        state=State.NOT_AFFECTED,
        justification=Justification.CODE_NOT_REACHABLE,
        confidence=Confidence.HIGH,
        evidence_refs=["ai:CVE-2024-0001:confirmed"],
        missing_evidence=[],
    )


def _reject_verdict() -> AiVerdictDto:
    return AiVerdictDto(
        state=State.AFFECTED,
        justification=None,
        confidence=Confidence.HIGH,
        evidence_refs=["ai:CVE-2024-0001:reachable"],
        missing_evidence=[],
    )


def _abstain_verdict() -> AiVerdictDto:
    return AiVerdictDto(
        state=State.UNDER_INVESTIGATION,
        justification=None,
        confidence=Confidence.INSUFFICIENT,
        evidence_refs=[],
        missing_evidence=["conclusive reference scan"],
    )


class _StubAdjudicator:
    """Returns each verdict in ``verdicts`` in order, repeating the last.
    ``allow_calls=False`` fails the test loudly if the AI is ever consulted
    at all — used to prove branches that must never call it."""

    def __init__(self, *verdicts: AiVerdictDto, allow_calls: bool = True) -> None:
        self._verdicts = list(verdicts)
        self._allow_calls = allow_calls
        self.calls = 0

    async def adjudicate(self, pack: EvidencePack, finding: FindingRef) -> AiVerdictDto:
        if not self._allow_calls:
            raise AssertionError("adjudicator must not be called on this path")
        self.calls += 1
        index = min(self.calls - 1, len(self._verdicts) - 1)
        return self._verdicts[index]


class _StubIq:
    def __init__(
        self,
        *,
        vuln: VulnDetail = _VULN,
        link_id: str = "application|app-1|waiver-1",
        create_error: Exception | None = None,
        allow_create: bool = True,
    ) -> None:
        self._vuln = vuln
        self._link_id = link_id
        self._create_error = create_error
        self._allow_create = allow_create
        self.create_calls = 0

    async def applications_for_user(self, user_token: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def report(self, application_id: str, report_id: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def vulnerability(self, vuln_id: str, component_purl: str | None) -> VulnDetail:
        return self._vuln

    async def remediation(self, application_id: str, purl: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def source_control(self, application_id: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def create_determination(
        self, finding: FindingRef, options: DeterminationOptions
    ) -> str:
        if not self._allow_create:
            raise AssertionError("iq.create_determination must not be called on this path")
        self.create_calls += 1
        if self._create_error is not None:
            raise self._create_error
        return self._link_id

    async def revoke_determination(self, link_id: str) -> None:  # pragma: no cover - unused
        raise NotImplementedError


async def _new_finding(
    session: AsyncSession, *, cve: str = "CVE-2024-0001"
) -> tuple[Assessment, Finding]:
    assessment = Assessment(application_id="app-1", report_id="report-1", requester="tester")
    session.add(assessment)
    await session.flush()
    finding = Finding(assessment_id=assessment.id, cve=cve, purl="pkg:maven/x/y@1.0?type=jar")
    session.add(finding)
    await session.flush()
    return assessment, finding


def _tier1_clear_outcome() -> EngineOutcome:
    return EngineOutcome(
        proposed=FindingOutcome.NOT_AFFECTED,
        tier=EvidenceTier.PROOF,
        justification=Justification.CODE_NOT_PRESENT,
        requires_second_confirmation=False,
        blocked_by=frozenset(),
        results=(
            RuleEvaluation(
                rule_id="t1-class-absent",
                rule_version="1",
                tier=EvidenceTier.PROOF,
                verdict=RuleVerdict.SATISFIED,
                justification=Justification.CODE_NOT_PRESENT,
                detail={"cve": "CVE-2024-0001"},
            ),
        ),
    )


def _tier2_clear_outcome() -> EngineOutcome:
    return EngineOutcome(
        proposed=FindingOutcome.NOT_AFFECTED,
        tier=EvidenceTier.STRONG,
        justification=Justification.CODE_NOT_REACHABLE,
        requires_second_confirmation=True,
        blocked_by=frozenset(),
        results=(
            RuleEvaluation(
                rule_id="t2-not-referenced",
                rule_version="1",
                tier=EvidenceTier.STRONG,
                verdict=RuleVerdict.SATISFIED,
                justification=Justification.CODE_NOT_REACHABLE,
                detail={"cve": "CVE-2024-0001"},
            ),
        ),
    )


def _kev_blocked_outcome() -> EngineOutcome:
    return EngineOutcome(
        proposed=FindingOutcome.NEEDS_REVIEW,
        tier=None,
        justification=None,
        requires_second_confirmation=False,
        blocked_by=frozenset({"kev"}),
        results=(
            RuleEvaluation(
                rule_id="t1-class-absent",
                rule_version="1",
                tier=EvidenceTier.PROOF,
                verdict=RuleVerdict.SATISFIED,
                justification=Justification.CODE_NOT_PRESENT,
                detail={"cve": "CVE-2024-0001"},
            ),
            RuleEvaluation(
                rule_id="t3-kev",
                rule_version="1",
                tier=EvidenceTier.ESCALATION,
                verdict=RuleVerdict.SATISFIED,
                justification=None,
                detail={"cve": "CVE-2024-0001", "kev": True},
            ),
        ),
    )


def _no_fix_available_outcome() -> EngineOutcome:
    return EngineOutcome(
        proposed=FindingOutcome.NEEDS_REVIEW,
        tier=None,
        justification=None,
        requires_second_confirmation=False,
        blocked_by=frozenset(),
        results=(
            RuleEvaluation(
                rule_id="t3-no-fix-available",
                rule_version="1",
                tier=EvidenceTier.ESCALATION,
                verdict=RuleVerdict.SATISFIED,
                justification=None,
                detail={"cve": "CVE-2024-0001", "fix_available": False},
            ),
        ),
    )


def _middle_band_outcome() -> EngineOutcome:
    return EngineOutcome(
        proposed=FindingOutcome.NEEDS_REVIEW,
        tier=None,
        justification=None,
        requires_second_confirmation=False,
        blocked_by=frozenset(),
        results=(),
    )


async def test_tier1_clear_commits_not_affected_without_calling_ai(session: AsyncSession) -> None:
    assessment, finding = await _new_finding(session)
    adjudicator = _StubAdjudicator(allow_calls=False)
    iq = _StubIq()

    result = await determine(
        finding,
        assessment,
        _tier1_clear_outcome(),
        PACK,
        session=session,
        iq=iq,
        adjudicator=adjudicator,
        actor="tester",
    )
    await session.commit()

    assert result.outcome is FindingOutcome.NOT_AFFECTED
    assert result.tier is EvidenceTier.PROOF
    assert result.justification is Justification.CODE_NOT_PRESENT
    assert iq.create_calls == 1

    links = (await session.execute(select(IqDeterminationLink))).scalars().all()
    assert len(links) == 1
    assert links[0].finding_id == finding.id
    assert links[0].expiry - datetime.now(UTC) > timedelta(days=6, hours=23)


async def test_kev_hard_blocker_routes_to_needs_review_without_ai_or_iq(
    session: AsyncSession,
) -> None:
    assessment, finding = await _new_finding(session)
    adjudicator = _StubAdjudicator(allow_calls=False)
    iq = _StubIq(allow_create=False)

    result = await determine(
        finding,
        assessment,
        _kev_blocked_outcome(),
        PACK,
        session=session,
        iq=iq,
        adjudicator=adjudicator,
        actor="tester",
    )

    assert result.outcome is FindingOutcome.NEEDS_REVIEW
    assert result.tier is None
    assert result.justification is None
    assert iq.create_calls == 0


async def test_no_fix_available_routes_to_risk_acceptance_and_commits_nothing_to_iq(
    session: AsyncSession,
) -> None:
    assessment, finding = await _new_finding(session)
    adjudicator = _StubAdjudicator(allow_calls=False)
    iq = _StubIq(allow_create=False)

    result = await determine(
        finding,
        assessment,
        _no_fix_available_outcome(),
        PACK,
        session=session,
        iq=iq,
        adjudicator=adjudicator,
        actor="tester",
    )

    assert result.outcome is FindingOutcome.RISK_ACCEPTANCE_REQUIRED
    assert result.justification is None
    assert result.tier is None
    assert iq.create_calls == 0

    links = (await session.execute(select(IqDeterminationLink))).scalars().all()
    assert links == []


async def test_tier2_clear_confirmed_by_ai_commits_not_affected(session: AsyncSession) -> None:
    assessment, finding = await _new_finding(session)
    adjudicator = _StubAdjudicator(_clear_verdict(), _clear_verdict())
    iq = _StubIq()

    result = await determine(
        finding,
        assessment,
        _tier2_clear_outcome(),
        PACK,
        session=session,
        iq=iq,
        adjudicator=adjudicator,
        actor="tester",
    )

    assert result.outcome is FindingOutcome.NOT_AFFECTED
    assert result.tier is EvidenceTier.STRONG
    assert adjudicator.calls == 2  # primary + refute
    assert iq.create_calls == 1


async def test_tier2_clear_disputed_by_ai_routes_to_needs_review(session: AsyncSession) -> None:
    assessment, finding = await _new_finding(session)
    adjudicator = _StubAdjudicator(_clear_verdict(), _reject_verdict())
    iq = _StubIq(allow_create=False)

    result = await determine(
        finding,
        assessment,
        _tier2_clear_outcome(),
        PACK,
        session=session,
        iq=iq,
        adjudicator=adjudicator,
        actor="tester",
    )

    assert result.outcome is FindingOutcome.NEEDS_REVIEW
    assert iq.create_calls == 0


async def test_middle_band_confident_reject_commits_affected_without_iq(
    session: AsyncSession,
) -> None:
    assessment, finding = await _new_finding(session)
    adjudicator = _StubAdjudicator(_reject_verdict())
    iq = _StubIq(allow_create=False)

    result = await determine(
        finding,
        assessment,
        _middle_band_outcome(),
        PACK,
        session=session,
        iq=iq,
        adjudicator=adjudicator,
        actor="tester",
    )

    assert result.outcome is FindingOutcome.AFFECTED
    assert adjudicator.calls == 1  # no refute pass on a reject
    assert iq.create_calls == 0


async def test_middle_band_abstention_routes_to_needs_review(session: AsyncSession) -> None:
    assessment, finding = await _new_finding(session)
    adjudicator = _StubAdjudicator(_abstain_verdict())
    iq = _StubIq(allow_create=False)

    result = await determine(
        finding,
        assessment,
        _middle_band_outcome(),
        PACK,
        session=session,
        iq=iq,
        adjudicator=adjudicator,
        actor="tester",
    )

    assert result.outcome is FindingOutcome.NEEDS_REVIEW
    assert iq.create_calls == 0


async def test_middle_band_confirmed_clear_commits_not_affected(session: AsyncSession) -> None:
    assessment, finding = await _new_finding(session)
    adjudicator = _StubAdjudicator(_clear_verdict(), _clear_verdict())
    iq = _StubIq()

    result = await determine(
        finding,
        assessment,
        _middle_band_outcome(),
        PACK,
        session=session,
        iq=iq,
        adjudicator=adjudicator,
        actor="tester",
    )

    assert result.outcome is FindingOutcome.NOT_AFFECTED
    assert result.tier is EvidenceTier.STRONG
    assert iq.create_calls == 1


def test_build_not_affected_determination_rejects_an_escalation_tier() -> None:
    with pytest.raises(DeterminationError, match="may not justify"):
        build_not_affected_determination(
            tier=EvidenceTier.ESCALATION,
            justification=Justification.CODE_NOT_PRESENT,
            confidence=Confidence.HIGH,
            evidence_refs=("x",),
        )


async def test_failed_validate_blocks_persistence_and_the_iq_call(session: AsyncSession) -> None:
    """A hand-built, internally-inconsistent EngineOutcome — claiming a
    NOT_AFFECTED clear via a Tier-3-only justification. The real RuleEngine
    can never produce this (``_best_clearing_result`` only selects a
    justification that ``justifies_determination()`` permits), but
    ``determine()`` must still refuse to act on it rather than trusting its
    input blindly.
    """
    assessment, finding = await _new_finding(session)
    bad_outcome = EngineOutcome(
        proposed=FindingOutcome.NOT_AFFECTED,
        tier=EvidenceTier.PROOF,
        justification=Justification.PROTECTED_AT_PERIMETER,
        requires_second_confirmation=False,
        blocked_by=frozenset(),
        results=(),
    )
    adjudicator = _StubAdjudicator(allow_calls=False)
    iq = _StubIq(allow_create=False)

    with pytest.raises(DeterminationError):
        await determine(
            finding,
            assessment,
            bad_outcome,
            PACK,
            session=session,
            iq=iq,
            adjudicator=adjudicator,
            actor="tester",
        )

    assert iq.create_calls == 0
    assert finding.outcome is None
    rule_results = (await session.execute(select(RuleResult))).scalars().all()
    assert rule_results == []


async def test_audit_entry_is_written_for_a_determination(session: AsyncSession) -> None:
    assessment, finding = await _new_finding(session)
    adjudicator = _StubAdjudicator(allow_calls=False)
    iq = _StubIq()

    await determine(
        finding,
        assessment,
        _tier1_clear_outcome(),
        PACK,
        session=session,
        iq=iq,
        adjudicator=adjudicator,
        actor="tester",
    )

    entries = (await session.execute(select(AuditEntry))).scalars().all()
    assert len(entries) == 1
    assert entries[0].subject_id == finding.id
    assert entries[0].action == "finding.determined.not_affected"
    assert entries[0].actor == "tester"


async def test_missing_suppression_id_raises_and_is_not_swallowed(session: AsyncSession) -> None:
    assessment, finding = await _new_finding(session)
    adjudicator = _StubAdjudicator(allow_calls=False)
    iq = _StubIq(create_error=DeterminationIdUnresolved("no matching waiver found"))

    with pytest.raises(DeterminationIdUnresolved):
        await determine(
            finding,
            assessment,
            _tier1_clear_outcome(),
            PACK,
            session=session,
            iq=iq,
            adjudicator=adjudicator,
            actor="tester",
        )

    assert finding.outcome is None
    links = (await session.execute(select(IqDeterminationLink))).scalars().all()
    assert links == []
