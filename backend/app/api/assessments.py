"""Assessment endpoints — ``POST /api/assessments``, ``GET /api/assessments``,
``GET /api/assessments/{id}``, ``GET /api/applications``.

Serves [2] New Assessment, [3] My Assessments and [4] Assessment Result
(``docs/design/ui-spec.md``). ``POST /api/assessments`` is the one place in
the API that runs the whole pipeline — admission, then evidence collection,
then the rule engine and the determination service, per finding — because
nothing else in this system runs it: there is no background worker or task
queue here (``pyproject.toml`` carries none, and the brief permits no new
dependency), so "raise an assessment... watch it reach a determination" (the
brief's own verification script) has to happen synchronously inside this one
request for a determination to exist by the time a later ``GET`` or the
review queue (``app/api/review.py``) looks for it. This route module never
reimplements decision logic itself — every decision is made by
``app.services.admission.admit``, ``app.services.collection.collect_evidence``,
``app.rules.engine.RuleEngine`` and ``app.services.determination.determine``;
this module only sequences those calls and shapes their output for the
screens that asked for it.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.errors import AdapterError
from app.adapters.protocols import Adjudicator, ArtifactStore, IqClient, RawReport, SourceRepository
from app.api.deps import (
    get_adjudicator_dep,
    get_artifact_store_dep,
    get_current_session,
    get_iq_client_dep,
    get_source_repository_dep,
    requires,
)
from app.db import get_session
from app.evidence.pack import ComponentEvidence
from app.middleware.session import SessionData
from app.repos.models import (
    AiVerdict as AiVerdictRow,
)
from app.repos.models import (
    Assessment,
    AssessmentState,
    AuditEntry,
    Evidence,
    Finding,
    FindingOutcome,
    RuleConfig,
    RuleResult,
)
from app.rules.engine import RuleEngine, RuleVerdict, Tier3Signals
from app.rules.registry import ACTIVE_RULES
from app.schemas.assessments import (
    AdmissionFailureOut,
    ApplicationOut,
    AssessmentDetail,
    AssessmentSummary,
    FindingOut,
    RaiseAssessmentRequest,
)
from app.schemas.common import OutcomeCounts, plain_language_reason
from app.services.admission import (
    AdmissionError,
    ArtifactUnavailable,
    ProvenanceMismatch,
    ReportUnavailable,
    admit,
)
from app.services.authorization import Capability, has_capability
from app.services.collection import CollectionError, collect_evidence
from app.services.determination import determine

router = APIRouter(tags=["assessments"])

#: Determinations expire 7 days after commit (CLAUDE.md rule 4) — mirrors
#: ``app.services.determination._EXPIRY``, applied here at the
#: assessment-aggregate level rather than imported: that constant is
#: private to the determination service, and the assessment-level expiry is
#: a display aggregate over per-finding ``IqDeterminationLink.expiry`` values
#: that are, in practice, all created within the same request.
_EXPIRY = timedelta(days=7)


def _iq_user_token(session: SessionData) -> str:
    """The token passed to ``IqClient.applications_for_user`` to scope the
    application list to the caller's own Nexus IQ entitlement.

    **No data source exists for this today — flagged in the task report.**
    Neither the LOCAL nor the LDAP auth provider (``app/auth/{local,ldap}.py``)
    issues or stores a per-user Nexus IQ token; the portal session carries
    only a username and portal roles, nothing IQ-specific. Using the portal
    username as a placeholder keeps this call site honest about "there is no
    real per-user IQ credential yet" rather than silently reusing the
    service account's own token, which would defeat the entitlement scoping
    this Protocol method exists for (``docs/design.md``, RBAC) — a requester
    would then see every application the *service* account can read, not
    their own. Against the fakes this is moot (``fakes/iq``'s
    ``/api/v2/applications`` route ignores the bearer token entirely), so it
    behaves correctly today, but a real Nexus IQ deployment needs a genuine
    per-user token/identity exchange before this scoping is real.
    """
    return session.username


def _outcome_counts(findings: Sequence[Finding]) -> OutcomeCounts:
    counts = OutcomeCounts()
    for finding in findings:
        if finding.outcome is FindingOutcome.NOT_AFFECTED:
            counts.not_affected += 1
        elif finding.outcome is FindingOutcome.AFFECTED:
            counts.affected += 1
        elif finding.outcome is FindingOutcome.NEEDS_REVIEW:
            counts.needs_review += 1
        elif finding.outcome is FindingOutcome.RISK_ACCEPTANCE_REQUIRED:
            counts.risk_acceptance_required += 1
    return counts


def recompute_assessment_state(assessment: Assessment, findings: Sequence[Finding]) -> None:
    """Roll every finding's outcome up into the assessment's own state.

    Shared with ``app/api/review.py``'s ``/decide`` endpoint, which mutates a
    single finding and then must re-derive the same aggregate — this is
    aggregation over already-decided outcomes, never a new decision, so
    sharing it does not violate "routes must not reimplement decision
    logic."  ``findings`` must be every ``Finding`` belonging to
    ``assessment``, not only the ones a caller just touched.
    """
    if any(finding.outcome is FindingOutcome.NEEDS_REVIEW for finding in findings):
        assessment.state = AssessmentState.NEEDS_REVIEW
        return
    assessment.state = AssessmentState.COMPLETED
    if assessment.expires_at is None and any(
        finding.outcome is FindingOutcome.NOT_AFFECTED for finding in findings
    ):
        assessment.expires_at = datetime.now(UTC) + _EXPIRY


def _admission_check_name(exc: AdmissionError) -> Literal["report", "artifact", "provenance"]:
    if isinstance(exc, ReportUnavailable):
        return "report"
    if isinstance(exc, ArtifactUnavailable):
        return "artifact"
    assert isinstance(exc, ProvenanceMismatch)
    return "provenance"


async def _build_rule_engine(db: AsyncSession) -> RuleEngine:
    """The rule engine, respecting any admin overrides in ``rule_config``.

    A Tier 1/2 rule with ``auto_determination_enabled=False`` is left out of
    the engine's own rule list entirely for this run — ``app/rules/engine.py``
    is out of this task's file scope and must not be modified to add a
    per-rule enable flag, so "disabled" is implemented as "not registered for
    this evaluation", which has the same effect: the rule can neither clear a
    finding nor force review via an UNANSWERABLE result. Tier 3 rules are
    never filtered — they have no toggle at all (task-6 brief).
    """
    configs = {c.rule_id: c for c in (await db.execute(select(RuleConfig))).scalars()}
    rules = [
        rule
        for rule in ACTIVE_RULES
        if rule.id not in configs or configs[rule.id].auto_determination_enabled
    ]
    epss_config = configs.get("t3-epss")
    threshold = epss_config.thresholds_json.get("hard_block_threshold") if epss_config else None
    if threshold is None:
        return RuleEngine(rules)
    return RuleEngine(rules, epss_threshold=float(threshold))


async def _run_pipeline(
    assessment: Assessment,
    report: RawReport,
    db: AsyncSession,
    *,
    iq: IqClient,
    artifact_store: ArtifactStore,
    source_repository: SourceRepository,
    adjudicator: Adjudicator,
    actor: str,
) -> list[Finding]:
    """Collect evidence, create a ``Finding`` per violation, and run each
    through the rule engine and the determination service.

    Raises:
        CollectionError: evidence collection could not proceed at all — see
            ``app.services.collection``'s own docstring. Not caught here;
            the caller decides how to surface it.
    """
    collected = await collect_evidence(
        assessment.application_id,
        assessment.report_id,
        assessment.artifact_ref or "",
        assessment_id=assessment.id,
        iq=iq,
        artifact_store=artifact_store,
        source_repository=source_repository,
        session=db,
    )
    if collected.source_control is not None:
        assessment.repository_url = collected.source_control.repository_url

    engine = await _build_rule_engine(db)
    components_by_cve = {component.cve: component for component in collected.pack.components}

    findings: list[Finding] = []
    for violation in report.violations:
        finding = Finding(
            assessment_id=assessment.id,
            cve=violation.cve,
            purl=violation.purl,
            policy_id=violation.policy_id,
            violation_id_snapshot=violation.violation_id,
            threat_level=violation.threat_level,
        )
        db.add(finding)
        await db.flush()

        component = components_by_cve.get(violation.cve) or ComponentEvidence(
            cve=violation.cve,
            class_paths=[],
            class_present=False,
            referenced=False,
            reference_scan_conclusive=False,
        )
        tier3_signals = collected.tier3_signals.get(violation.cve, Tier3Signals())
        engine_outcome = engine.evaluate_component(collected.pack, component, tier3_signals)

        await determine(
            finding,
            assessment,
            engine_outcome,
            collected.pack,
            session=db,
            iq=iq,
            adjudicator=adjudicator,
            actor=actor,
        )
        findings.append(finding)

    return findings


def derive_evidence_refs(
    finding: Finding, rule_results: Sequence[RuleResult], ai_verdict: AiVerdictRow | None
) -> list[str]:
    """Reconstruct the evidence references behind a committed clear from
    already-persisted rows.

    Not a new decision: ``app.services.determination.determine`` already
    decided and persisted the outcome; this only re-derives the same
    reference strings its own ``_rule_evidence_refs`` would have built, for
    display, from data that was never itself stored as a flat ref list on
    ``Finding``.
    """
    if finding.outcome is not FindingOutcome.NOT_AFFECTED:
        return []
    if ai_verdict is not None and ai_verdict.evidence_refs_json:
        return list(ai_verdict.evidence_refs_json)
    refs = [
        f"rule:{result.rule_id}:{result.rule_version}:{finding.cve}"
        for result in rule_results
        if result.tier is finding.tier
        and (result.detail_json or {}).get("rule_verdict") == RuleVerdict.SATISFIED.value
    ]
    return refs or [f"rule:unknown:{finding.cve}"]


async def latest_blocked_by(db: AsyncSession, finding_id: str) -> set[str]:
    result = await db.execute(
        select(AuditEntry)
        .where(AuditEntry.subject_type == "finding", AuditEntry.subject_id == finding_id)
        .order_by(AuditEntry.created_at.desc())
        .limit(1)
    )
    entry = result.scalars().first()
    if entry is None or entry.detail_json is None:
        return set()
    return set(entry.detail_json.get("blocked_by") or [])


async def _finding_out(db: AsyncSession, finding: Finding) -> FindingOut:
    rule_results = (
        (await db.execute(select(RuleResult).where(RuleResult.finding_id == finding.id)))
        .scalars()
        .all()
    )
    ai_verdict = (
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
    missing_evidence = list(ai_verdict.missing_evidence_json) if ai_verdict is not None else []
    evidence_refs = derive_evidence_refs(finding, rule_results, ai_verdict)
    reason = plain_language_reason(
        outcome=finding.outcome,
        tier=finding.tier,
        justification=finding.justification,
        blocked_by=blocked_by,
        missing_evidence=missing_evidence,
    )
    return FindingOut(
        id=finding.id,
        cve=finding.cve,
        purl=finding.purl,
        outcome=finding.outcome,
        reason=reason,
        tier=finding.tier,
        justification=finding.justification,
        confidence=finding.confidence,
        evidence_refs=evidence_refs,
        decided_at=finding.decided_at,
    )


async def _latest_admission_failure(
    db: AsyncSession, assessment_id: str
) -> AdmissionFailureOut | None:
    result = await db.execute(
        select(AuditEntry)
        .where(
            AuditEntry.subject_type == "assessment",
            AuditEntry.subject_id == assessment_id,
            AuditEntry.action == "assessment.admission_failed",
        )
        .order_by(AuditEntry.created_at.desc())
        .limit(1)
    )
    entry = result.scalars().first()
    if entry is None or entry.detail_json is None:
        return None
    detail = entry.detail_json
    return AdmissionFailureOut(check=detail["check"], message=detail["message"])


async def _provenance_snapshot(db: AsyncSession, assessment_id: str) -> dict[str, object] | None:
    result = await db.execute(
        select(Evidence)
        .where(
            Evidence.assessment_id == assessment_id,
            Evidence.collector == "provenance",
            Evidence.key == "fingerprint",
        )
        .limit(1)
    )
    row = result.scalars().first()
    return dict(row.value_json) if row is not None else None


async def _assessment_summary(db: AsyncSession, assessment: Assessment) -> AssessmentSummary:
    findings = (
        (await db.execute(select(Finding).where(Finding.assessment_id == assessment.id)))
        .scalars()
        .all()
    )
    admission_failure = None
    if assessment.state is AssessmentState.ADMISSION_FAILED:
        admission_failure = await _latest_admission_failure(db, assessment.id)
    return AssessmentSummary(
        id=assessment.id,
        application_id=assessment.application_id,
        report_id=assessment.report_id,
        state=assessment.state,
        requester=assessment.requester,
        requester_note=assessment.requester_note,
        finding_count=len(findings),
        outcome_counts=_outcome_counts(findings),
        created_at=assessment.created_at,
        submitted_at=assessment.submitted_at,
        expires_at=assessment.expires_at,
        admission_failure=admission_failure,
    )


async def _assessment_detail(db: AsyncSession, assessment: Assessment) -> AssessmentDetail:
    findings = (
        (
            await db.execute(
                select(Finding).where(Finding.assessment_id == assessment.id).order_by(Finding.cve)
            )
        )
        .scalars()
        .all()
    )
    finding_outs = [await _finding_out(db, finding) for finding in findings]
    admission_failure = None
    if assessment.state is AssessmentState.ADMISSION_FAILED:
        admission_failure = await _latest_admission_failure(db, assessment.id)
    provenance = await _provenance_snapshot(db, assessment.id)
    return AssessmentDetail(
        id=assessment.id,
        application_id=assessment.application_id,
        report_id=assessment.report_id,
        state=assessment.state,
        requester=assessment.requester,
        requester_note=assessment.requester_note,
        commit_sha=assessment.commit_sha,
        artifact_ref=assessment.artifact_ref,
        created_at=assessment.created_at,
        submitted_at=assessment.submitted_at,
        expires_at=assessment.expires_at,
        admission_failure=admission_failure,
        provenance=provenance,
        outcome_counts=_outcome_counts(findings),
        findings=finding_outs,
    )


@router.post(
    "/api/assessments", response_model=AssessmentDetail, status_code=status.HTTP_201_CREATED
)
async def raise_assessment(
    body: RaiseAssessmentRequest,
    session: SessionData = Depends(requires(Capability.RAISE_ASSESSMENT)),
    db: AsyncSession = Depends(get_session),
    iq: IqClient = Depends(get_iq_client_dep),
    artifact_store: ArtifactStore = Depends(get_artifact_store_dep),
    source_repository: SourceRepository = Depends(get_source_repository_dep),
    adjudicator: Adjudicator = Depends(get_adjudicator_dep),
) -> AssessmentDetail:
    """[2] New Assessment's submit action.

    Checks the caller's own Nexus IQ entitlement first (`GET /api/applications`'s
    own list) — the New Assessment form only ever lets a requester pick from
    that list, so a request naming an application outside it is refused
    before admission ever runs, distinctly from an admission-check failure.
    Then runs admission, then (on success) the full determination pipeline —
    see this module's docstring for why that all happens in one request.
    """
    try:
        applications = await iq.applications_for_user(_iq_user_token(session))
    except AdapterError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Nexus IQ is unreachable: {exc}",
        ) from exc
    if not any(application.id == body.application_id for application in applications):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="you do not have access to this application in Nexus IQ",
        )

    assessment = Assessment(
        application_id=body.application_id,
        report_id=body.report_id,
        artifact_ref=body.artifact_coordinates,
        commit_sha=body.commit_sha,
        requester=session.username,
        requester_note=body.requester_note,
        state=AssessmentState.ADMISSION,
    )
    db.add(assessment)
    await db.flush()

    try:
        admitted = await admit(
            body.application_id,
            body.report_id,
            body.artifact_coordinates,
            iq=iq,
            artifact_store=artifact_store,
        )
    except AdmissionError as exc:
        check = _admission_check_name(exc)
        assessment.state = AssessmentState.ADMISSION_FAILED
        db.add(
            AuditEntry(
                actor=session.username,
                action="assessment.admission_failed",
                subject_type="assessment",
                subject_id=assessment.id,
                detail_json={"check": check, "message": str(exc)},
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"check": check, "message": str(exc)},
        ) from exc

    assessment.scan_id = admitted.report.scan_id
    assessment.state = AssessmentState.ANALYSING
    assessment.submitted_at = datetime.now(UTC)
    await db.flush()

    try:
        findings = await _run_pipeline(
            assessment,
            admitted.report,
            db,
            iq=iq,
            artifact_store=artifact_store,
            source_repository=source_repository,
            adjudicator=adjudicator,
            actor=session.username,
        )
    except CollectionError as exc:
        db.add(
            AuditEntry(
                actor=session.username,
                action="assessment.analysis_failed",
                subject_type="assessment",
                subject_id=assessment.id,
                detail_json={"message": str(exc)},
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"evidence collection failed after admission succeeded: {exc}",
        ) from exc

    recompute_assessment_state(assessment, findings)
    await db.commit()

    return await _assessment_detail(db, assessment)


@router.get("/api/assessments", response_model=list[AssessmentSummary])
async def list_my_assessments(
    session: SessionData = Depends(requires(Capability.RAISE_ASSESSMENT)),
    db: AsyncSession = Depends(get_session),
) -> list[AssessmentSummary]:
    """[3] My Assessments — the caller's own, newest first."""
    assessments = (
        (
            await db.execute(
                select(Assessment)
                .where(Assessment.requester == session.username)
                .order_by(Assessment.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [await _assessment_summary(db, assessment) for assessment in assessments]


@router.get("/api/assessments/{assessment_id}", response_model=AssessmentDetail)
async def get_assessment(
    assessment_id: str,
    session: SessionData = Depends(get_current_session),
    db: AsyncSession = Depends(get_session),
) -> AssessmentDetail:
    """[4] Assessment Result for the requester who raised it; also serves
    [6] Assessment Detail's header for a reviewer/approver/auditor — see
    ``app/api/review.py`` for the findings table itself
    (``GET /api/review/findings?assessment_id=...``), which is the other
    half of that screen.
    """
    assessment = await db.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="assessment not found")

    is_owner = assessment.requester == session.username
    may_review = has_capability(session.roles, Capability.VIEW_QUEUE) or has_capability(
        session.roles, Capability.VIEW_DASHBOARD
    )
    if not (is_owner or may_review):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="you may not view this assessment"
        )

    return await _assessment_detail(db, assessment)


@router.get("/api/applications", response_model=list[ApplicationOut])
async def list_applications(
    session: SessionData = Depends(requires(Capability.RAISE_ASSESSMENT)),
    iq: IqClient = Depends(get_iq_client_dep),
) -> list[ApplicationOut]:
    """[2] New Assessment's application select — from IQ, scoped to the
    caller's token. See ``_iq_user_token``'s docstring for the (currently
    placeholder) scoping token.
    """
    try:
        applications = await iq.applications_for_user(_iq_user_token(session))
    except AdapterError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Nexus IQ is unreachable: {exc}",
        ) from exc
    return [
        ApplicationOut(id=application.id, name=application.name) for application in applications
    ]


__all__ = [
    "derive_evidence_refs",
    "latest_blocked_by",
    "recompute_assessment_state",
    "router",
]
