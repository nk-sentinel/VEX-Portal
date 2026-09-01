"""Review endpoints — the queue, the evidence drawer, and the two-step
recommend/decide commit flow.

Serves [5] Review Queue, [6] Assessment Detail (the same table, scoped by
``assessment_id`` — see ``docs/design/ui-spec.md``: "Screens 5 and 6 are one
component, differently scoped") and the Evidence Drawer overlay.

**``recommend`` vs ``decide``.** ``RECOMMEND_DETERMINATION`` (reviewer or
approver) and ``COMMIT_DETERMINATION`` (approver only) are deliberately
different capabilities (``app/services/authorization.py``). ``POST
.../recommend`` records a reviewer's proposal as an audit entry only — it
never mutates ``Finding`` or touches Nexus IQ, so a reviewer who can
recommend can never, by calling this endpoint, produce a side effect only an
approver's commit should have. ``POST .../decide`` is the one route in this
module that commits: it always re-checks separation of duties
(``assert_may_commit_own_determination``) and, for a ``not_affected``
outcome, delegates to ``app.services.determination.commit_reviewer_clear`` —
never a second implementation of ``determine()``'s own commit logic. That
service function calls ``Determination.validate()`` (via
``build_not_affected_determination``) before anything is persisted or sent
to IQ, exactly as ``determine()`` itself does, and is also the only place
anywhere reachable from this module that constructs
``app.repos.models.IqDeterminationLink`` or calls
``IqClient.create_determination`` — see that function's own docstring for
why the IQ-suppression bookkeeping lives in the service layer rather than
here.

**Committing here never bypasses the safety gates the automated pipeline
uses**, and this module does not re-check ``EngineOutcome.blocked_by``
before consulting anyone, because there is no AI to blind here: a human is
the one making the call, having already seen the full trace and escalation
signals in the drawer — the hard-blocker check inside ``determine()`` exists
specifically to keep a blind AI from seeing a KEV-blocked finding, a concern
that does not apply to a human who is looking straight at it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.protocols import IqClient
from app.api.assessments import (
    derive_evidence_refs,
    latest_blocked_by,
    recompute_assessment_state,
)
from app.api.deps import get_iq_client_dep, requires
from app.db import get_session
from app.domain.determination import Confidence, DeterminationError, EvidenceTier, State
from app.middleware.session import SessionData
from app.repos.models import (
    AiVerdict as AiVerdictRow,
)
from app.repos.models import (
    Assessment,
    AuditEntry,
    Finding,
    FindingOutcome,
    IqDeterminationLink,
    RuleResult,
)
from app.rules.engine import RuleVerdict
from app.schemas.common import (
    AiVerdictOut,
    EscalationSignals,
    RuleTraceEntry,
    plain_language_reason,
)
from app.schemas.review import (
    SLA_HOURS,
    SLA_URGENT_HOURS,
    DecideRequest,
    DeterminationOut,
    RecommendationOut,
    RecommendationRecorded,
    RecommendRequest,
    ReviewFindingDetail,
    ReviewFindingRow,
    SlaBand,
)
from app.services.authorization import (
    Capability,
    SeparationOfDutiesError,
    assert_may_commit_own_determination,
)
from app.services.determination import commit_reviewer_clear

router = APIRouter(prefix="/api/review", tags=["review"])

_EXPIRY = timedelta(days=7)

#: Which ESCALATION-tier rule result carries which `EscalationSignals` field
#: — see `app.rules.tier3` for each rule's `detail` shape.
_KEV_RULE_ID = "t3-kev"
_EPSS_RULE_ID = "t3-epss"
_CVSS_RULE_ID = "t3-cvss-vector"
_NO_FIX_RULE_ID = "t3-no-fix-available"


async def _load_finding_and_assessment(
    db: AsyncSession, finding_id: str
) -> tuple[Finding, Assessment]:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    assessment = await db.get(Assessment, finding.assessment_id)
    assert assessment is not None  # a Finding's assessment_id is a non-nullable FK
    return finding, assessment


def _sla(finding: Finding, assessment: Assessment) -> tuple[SlaBand, float | None, float]:
    """The SLA band/remaining-hours/age for one finding — see
    ``app.schemas.review``'s ``SLA_HOURS`` docstring for why this is a fixed
    policy constant rather than something admin-configurable.
    """
    reference = assessment.submitted_at or assessment.created_at
    age_hours = (datetime.now(UTC) - reference).total_seconds() / 3600.0
    if finding.outcome is not FindingOutcome.NEEDS_REVIEW:
        return "n/a", None, age_hours
    remaining = SLA_HOURS - age_hours
    band: SlaBand
    if remaining <= 0:
        band = "breaching"
    elif remaining <= SLA_URGENT_HOURS:
        band = "urgent"
    else:
        band = "ok"
    return band, remaining, age_hours


def _row_out(finding: Finding, assessment: Assessment) -> ReviewFindingRow:
    band, remaining, age_hours = _sla(finding, assessment)
    outcome = finding.outcome or FindingOutcome.NEEDS_REVIEW
    return ReviewFindingRow(
        id=finding.id,
        assessment_id=assessment.id,
        application_id=assessment.application_id,
        cve=finding.cve,
        purl=finding.purl,
        outcome=outcome,
        recommended_outcome=outcome,
        tier=finding.tier,
        justification=finding.justification,
        confidence=finding.confidence,
        sla_band=band,
        sla_hours_remaining=remaining,
        age_hours=age_hours,
        requester=assessment.requester,
        decided_by=finding.decided_by,
        decided_at=finding.decided_at,
    )


def _escalation_signals(rule_results: list[RuleResult], blocked_by: set[str]) -> EscalationSignals:
    """Build the escalation-signals object from the persisted ESCALATION-tier
    rule trace — never from ``rule_trace`` itself. See this module's, and
    ``app.schemas.common``'s, docstrings on why the two are never merged.
    """
    kev: bool | None = None
    epss: float | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    fix_available: bool | None = None
    for result in rule_results:
        if result.tier is not EvidenceTier.ESCALATION:
            continue
        detail = result.detail_json or {}
        if result.rule_id == _KEV_RULE_ID and "kev" in detail:
            kev = detail["kev"]
        elif result.rule_id == _EPSS_RULE_ID and "epss" in detail:
            epss = detail["epss"]
        elif result.rule_id == _CVSS_RULE_ID and "cvss_base_score" in detail:
            cvss_score = detail["cvss_base_score"]
            cvss_vector = detail.get("cvss_vector")
        elif result.rule_id == _NO_FIX_RULE_ID and "fix_available" in detail:
            fix_available = detail["fix_available"]
    return EscalationSignals(
        epss=epss,
        kev=kev,
        cvss_base_score=cvss_score,
        cvss_vector=cvss_vector,
        fix_available=fix_available,
        hard_blockers=sorted(blocked_by),
    )


async def _finding_detail(
    db: AsyncSession, finding: Finding, assessment: Assessment
) -> ReviewFindingDetail:
    rule_results = (
        (await db.execute(select(RuleResult).where(RuleResult.finding_id == finding.id)))
        .scalars()
        .all()
    )
    ai_row = (
        (
            await db.execute(
                select(AiVerdictRow)
                .where(AiVerdictRow.finding_id == finding.id)
                .order_by(AiVerdictRow.created_at.desc())
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    blocked_by = await latest_blocked_by(db, finding.id)
    missing_evidence = list(ai_row.missing_evidence_json) if ai_row is not None else []

    rule_trace = [
        RuleTraceEntry(
            rule_id=result.rule_id,
            rule_version=result.rule_version,
            tier=result.tier,
            verdict=(result.detail_json or {}).get("rule_verdict", result.verdict.value),
            detail=dict(result.detail_json or {}),
        )
        for result in rule_results
        if result.tier is not EvidenceTier.ESCALATION
    ]
    escalation = _escalation_signals(list(rule_results), blocked_by)

    outcome = finding.outcome or FindingOutcome.NEEDS_REVIEW
    reason = plain_language_reason(
        outcome=finding.outcome,
        tier=finding.tier,
        justification=finding.justification,
        blocked_by=blocked_by,
        missing_evidence=missing_evidence,
    )
    recommendation = RecommendationOut(
        outcome=outcome,
        reason=reason,
        tier=finding.tier,
        justification=finding.justification,
        confidence=finding.confidence,
        requires_second_confirmation=finding.tier is EvidenceTier.STRONG,
    )

    ai_verdict_out = (
        AiVerdictOut(
            model_id=ai_row.model_id,
            prompt_version=ai_row.prompt_version,
            state=ai_row.state,
            justification=ai_row.justification,
            confidence=ai_row.confidence,
            evidence_refs=list(ai_row.evidence_refs_json),
            missing_evidence=list(ai_row.missing_evidence_json),
            refuted_by=ai_row.refuted_by,
        )
        if ai_row is not None
        else None
    )

    determination = None
    if (
        finding.outcome is FindingOutcome.NOT_AFFECTED
        and finding.tier is not None
        and finding.justification is not None
        and finding.confidence is not None
        and finding.decided_by is not None
        and finding.decided_at is not None
    ):
        link = (
            (
                await db.execute(
                    select(IqDeterminationLink)
                    .where(IqDeterminationLink.finding_id == finding.id)
                    .order_by(IqDeterminationLink.created_at.desc())
                    .limit(1)
                )
            )
            .scalars()
            .first()
        )
        determination = DeterminationOut(
            tier=finding.tier,
            justification=finding.justification,
            confidence=finding.confidence,
            evidence_refs=derive_evidence_refs(finding, rule_results, ai_row),
            decided_by=finding.decided_by,
            decided_at=finding.decided_at,
            iq_suppressed=link is not None,
        )

    return ReviewFindingDetail(
        id=finding.id,
        assessment_id=assessment.id,
        application_id=assessment.application_id,
        cve=finding.cve,
        purl=finding.purl,
        threat_level=finding.threat_level,
        outcome=outcome,
        recommendation=recommendation,
        rule_trace=rule_trace,
        escalation=escalation,
        ai_verdict=ai_verdict_out,
        missing_evidence=missing_evidence,
        determination=determination,
    )


@router.get("/findings", response_model=list[ReviewFindingRow])
async def list_findings(
    state: list[str] | None = Query(None),
    application_id: str | None = Query(None),
    assessment_id: str | None = Query(None),
    tier: str | None = Query(None),
    sla: SlaBand | None = Query(None),
    search: str | None = Query(None),
    session: SessionData = Depends(requires(Capability.VIEW_QUEUE)),
    db: AsyncSession = Depends(get_session),
) -> list[ReviewFindingRow]:
    """[5] Review Queue / [6] Assessment Detail's table.

    No filter is applied by default — the caller (the queue's own "needs
    review" default filter chip) passes ``state=needs_review`` itself; this
    endpoint stays a general-purpose "findings across assessments" query so
    the same route serves the queue's every filter combination and screen
    6's `assessment_id` scoping without a second endpoint.
    """
    stmt = select(Finding, Assessment).join(Assessment, Finding.assessment_id == Assessment.id)
    if assessment_id:
        stmt = stmt.where(Finding.assessment_id == assessment_id)
    if application_id:
        stmt = stmt.where(Assessment.application_id == application_id)
    if state:
        try:
            outcomes = {FindingOutcome(value) for value in state}
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"unknown state filter: {exc}"
            ) from exc
        stmt = stmt.where(Finding.outcome.in_(outcomes))
    if tier:
        try:
            tier_value = EvidenceTier[tier.upper()]
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"unknown tier filter: {tier!r}"
            ) from exc
        stmt = stmt.where(Finding.tier == tier_value)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(or_(Finding.cve.ilike(like), Finding.purl.ilike(like)))

    rows = [_row_out(finding, assessment) for finding, assessment in (await db.execute(stmt)).all()]
    if sla is not None:
        rows = [row for row in rows if row.sla_band == sla]
    rows.sort(key=lambda row: (row.sla_hours_remaining is None, row.sla_hours_remaining or 0.0))
    return rows


@router.get("/findings/{finding_id}", response_model=ReviewFindingDetail)
async def get_finding(
    finding_id: str,
    session: SessionData = Depends(requires(Capability.VIEW_QUEUE)),
    db: AsyncSession = Depends(get_session),
) -> ReviewFindingDetail:
    """The Evidence Drawer's payload."""
    finding, assessment = await _load_finding_and_assessment(db, finding_id)
    return await _finding_detail(db, finding, assessment)


@router.post("/findings/{finding_id}/recommend", response_model=RecommendationRecorded)
async def recommend(
    finding_id: str,
    body: RecommendRequest,
    session: SessionData = Depends(requires(Capability.RECOMMEND_DETERMINATION)),
    db: AsyncSession = Depends(get_session),
) -> RecommendationRecorded:
    """A reviewer's non-binding proposal — an audit entry only. See this
    module's docstring for why this never mutates ``Finding`` or reaches IQ.
    """
    finding, _assessment = await _load_finding_and_assessment(db, finding_id)
    now = datetime.now(UTC)
    db.add(
        AuditEntry(
            actor=session.username,
            action="finding.recommended",
            subject_type="finding",
            subject_id=finding.id,
            detail_json={
                "outcome": body.outcome,
                "justification": body.justification.value if body.justification else None,
                "note": body.note,
            },
            created_at=now,
        )
    )
    await db.commit()
    return RecommendationRecorded(
        finding_id=finding.id, outcome=body.outcome, recorded_by=session.username, recorded_at=now
    )


def _achieved_clear(
    finding: Finding, rule_results: list[RuleResult], ai_row: AiVerdictRow | None, actor: str
) -> tuple[EvidenceTier, tuple[str, ...]] | None:
    """The strongest (lowest) evidence tier this finding's own persisted
    rule trace/AI verdict actually achieved, and the evidence references
    behind it — or ``None`` if nothing PROOF- or STRONG-tier ever cleared
    it.

    **The approver never supplies a tier — it is derived, never asserted.**
    ``docs/design/ui-spec.md``'s Evidence Drawer shows tier as read-only
    display ("A cleared verdict always shows its tier"); nothing lets a
    reviewer pick one. Deriving it here, from the same rows the drawer
    itself renders, means a commit can never claim stronger evidence than
    what was actually found — mirrors
    ``app.rules.engine.RuleEngine._best_clearing_result``'s "lowest tier
    wins" rule one layer up, over already-persisted, already-decided rows
    (never a new decision).

    A reviewer-provenance reference is always appended to whichever refs are
    found, so the result (when not ``None``) can never come back with empty
    ``evidence_refs`` — ``Determination.validate`` requires at least one.
    """
    proof_refs = [
        f"rule:{result.rule_id}:{result.rule_version}:{finding.cve}"
        for result in rule_results
        if result.tier is EvidenceTier.PROOF
        and (result.detail_json or {}).get("rule_verdict") == RuleVerdict.SATISFIED.value
    ]
    if proof_refs:
        return EvidenceTier.PROOF, (*proof_refs, f"reviewer:{actor}:{finding.id}")

    strong_refs = [
        f"rule:{result.rule_id}:{result.rule_version}:{finding.cve}"
        for result in rule_results
        if result.tier is EvidenceTier.STRONG
        and (result.detail_json or {}).get("rule_verdict") == RuleVerdict.SATISFIED.value
    ]
    if ai_row is not None and ai_row.state is State.NOT_AFFECTED and ai_row.evidence_refs_json:
        strong_refs = [*ai_row.evidence_refs_json, *strong_refs]
    if strong_refs:
        return EvidenceTier.STRONG, (*strong_refs, f"reviewer:{actor}:{finding.id}")

    return None


@router.post("/findings/{finding_id}/decide", response_model=ReviewFindingRow)
async def decide(
    finding_id: str,
    body: DecideRequest,
    session: SessionData = Depends(requires(Capability.COMMIT_DETERMINATION)),
    db: AsyncSession = Depends(get_session),
    iq: IqClient = Depends(get_iq_client_dep),
) -> ReviewFindingRow:
    """The approver's commit action — creates the IQ suppression for a
    committed ``not_affected``, nothing for a committed ``affected``.
    """
    finding, assessment = await _load_finding_and_assessment(db, finding_id)

    try:
        assert_may_commit_own_determination(assessment=assessment, actor_username=session.username)
    except SeparationOfDutiesError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    now = datetime.now(UTC)

    if body.outcome == "not_affected":
        if body.justification is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="justification is required to commit not_affected",
            )

        rule_results = (
            (await db.execute(select(RuleResult).where(RuleResult.finding_id == finding.id)))
            .scalars()
            .all()
        )
        ai_row = (
            (
                await db.execute(
                    select(AiVerdictRow)
                    .where(AiVerdictRow.finding_id == finding.id)
                    .order_by(AiVerdictRow.created_at.desc())
                    .limit(1)
                )
            )
            .scalars()
            .first()
        )
        achieved = _achieved_clear(finding, list(rule_results), ai_row, session.username)
        if achieved is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    "no PROOF or STRONG evidence exists on this finding's rule trace to "
                    "support a not_affected determination"
                ),
            )
        tier, evidence_refs = achieved

        if tier is EvidenceTier.STRONG and (
            not body.second_confirmer or body.second_confirmer == session.username
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    "a Tier 2 (STRONG) clear requires an independent second confirmation — "
                    "name a confirmer other than yourself"
                ),
            )

        confidence = Confidence.HIGH

        try:
            # Shares the same last-gate validate() and the same IQ-suppression
            # bookkeeping determine() itself uses — see
            # app.services.determination.commit_reviewer_clear's own
            # docstring for why constructing the IQ-link row happens there,
            # never in this route module.
            await commit_reviewer_clear(
                finding,
                assessment,
                tier=tier,
                justification=body.justification,
                confidence=confidence,
                evidence_refs=evidence_refs,
                session=db,
                iq=iq,
            )
        except DeterminationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
            ) from exc
    else:
        finding.outcome = FindingOutcome.AFFECTED
        finding.tier = None
        finding.justification = None
        finding.confidence = Confidence.HIGH

    finding.decided_by = session.username
    finding.decided_at = now
    # commit_reviewer_clear (called above, out of this module) sets
    # finding.outcome for the not_affected branch; the else branch sets it
    # inline. Either way it is never None once this point is reached — mypy
    # cannot see the narrowing across that function call, hence the assert.
    assert finding.outcome is not None

    db.add(
        AuditEntry(
            actor=session.username,
            action=f"finding.determined.{finding.outcome.value}",
            subject_type="finding",
            subject_id=finding.id,
            detail_json={
                "assessment_id": assessment.id,
                "cve": finding.cve,
                "purl": finding.purl,
                "tier": finding.tier.value if finding.tier else None,
                "justification": finding.justification.value if finding.justification else None,
                "confidence": finding.confidence.value if finding.confidence else None,
                "note": body.note,
                "second_confirmer": body.second_confirmer,
                "committed_via": "review.decide",
            },
            created_at=now,
        )
    )

    all_findings = (
        (await db.execute(select(Finding).where(Finding.assessment_id == assessment.id)))
        .scalars()
        .all()
    )
    recompute_assessment_state(assessment, all_findings)

    await db.commit()
    return _row_out(finding, assessment)


__all__ = ["router"]
