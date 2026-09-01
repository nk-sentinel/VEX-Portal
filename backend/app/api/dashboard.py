"""Dashboard endpoints — [7] Dashboard (Auditor, Management).

One route per panel — see ``app.schemas.dashboard``'s module docstring for
why. Every panel that scopes by time defaults to the last 30 days when
``since``/``until`` are not supplied; every panel that can be scoped by
``application_id`` accepts it, except the per-rule agreement panel (a rule's
trustworthiness is portal-wide, not per-application — see
``app.schemas.dashboard.AgreementPanel``'s own docstring).

Numbers here are computed straight from the same rows the queue and
assessment endpoints read (``Finding``, ``Assessment``, ``RuleResult``) —
this module holds no separate aggregate/materialised-view table, so
"dashboard numbers match the underlying rows" (task-6 brief) is true by
construction, not by a reconciliation job that could drift.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.admin import compute_rule_agreement
from app.api.assessments import is_automated_decision
from app.api.deps import requires
from app.db import get_session
from app.domain.determination import EvidenceTier
from app.middleware.session import SessionData
from app.repos.models import Assessment, Finding, FindingOutcome, RuleConfig
from app.rules.registry import ACTIVE_RULES
from app.schemas.dashboard import (
    AgreementPanel,
    AutomationSplitPanel,
    ExpiryPanel,
    OutcomeMixPanel,
    OutcomeMixRow,
    RuleAgreementOut,
    SlaPanel,
    VolumePanel,
)
from app.schemas.review import SLA_HOURS
from app.services.authorization import Capability

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

_DEFAULT_WINDOW = timedelta(days=30)
_EXPIRY_LOOKAHEAD = timedelta(days=7)


def _window(since: datetime | None, until: datetime | None) -> tuple[datetime, datetime]:
    end = until or datetime.now(UTC)
    start = since or (end - _DEFAULT_WINDOW)
    return start, end


def _percentile(sorted_values: list[float], pct: float) -> float | None:
    """Linear-interpolation percentile — the standard definition, no
    external stats dependency needed for six numbers."""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (len(sorted_values) - 1) * (pct / 100)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return sorted_values[int(rank)]
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * (rank - lower)


@router.get("/volume", response_model=VolumePanel)
async def volume(
    application_id: str | None = Query(None),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    session: SessionData = Depends(requires(Capability.VIEW_DASHBOARD)),
    db: AsyncSession = Depends(get_session),
) -> VolumePanel:
    start, end = _window(since, until)

    assessment_stmt = select(Assessment).where(
        Assessment.created_at >= start, Assessment.created_at <= end
    )
    if application_id:
        assessment_stmt = assessment_stmt.where(Assessment.application_id == application_id)
    assessments = (await db.execute(assessment_stmt)).scalars().all()

    finding_stmt = (
        select(Finding)
        .join(Assessment, Finding.assessment_id == Assessment.id)
        .where(Assessment.created_at >= start, Assessment.created_at <= end)
    )
    if application_id:
        finding_stmt = finding_stmt.where(Assessment.application_id == application_id)
    findings = (await db.execute(finding_stmt)).scalars().all()

    counts: dict[str, int] = {}
    for finding in findings:
        key = finding.outcome.value if finding.outcome is not None else "needs_review"
        counts[key] = counts.get(key, 0) + 1

    return VolumePanel(
        since=start,
        until=end,
        total_assessments=len(assessments),
        total_findings=len(findings),
        findings_by_outcome=counts,
    )


@router.get("/automation-split", response_model=AutomationSplitPanel)
async def automation_split(
    application_id: str | None = Query(None),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    session: SessionData = Depends(requires(Capability.VIEW_DASHBOARD)),
    db: AsyncSession = Depends(get_session),
) -> AutomationSplitPanel:
    start, end = _window(since, until)
    stmt = (
        select(Finding)
        .join(Assessment, Finding.assessment_id == Assessment.id)
        .where(
            Finding.decided_at.is_not(None), Finding.decided_at >= start, Finding.decided_at <= end
        )
    )
    if application_id:
        stmt = stmt.where(Assessment.application_id == application_id)
    findings = (await db.execute(stmt)).scalars().all()

    automated = sum(1 for finding in findings if is_automated_decision(finding))
    total = len(findings)
    ratio = automated / total if total else None

    return AutomationSplitPanel(
        since=start,
        until=end,
        total_decided=total,
        automated=automated,
        human_reviewed=total - automated,
        automated_ratio=ratio,
    )


@router.get("/sla", response_model=SlaPanel)
async def sla(
    application_id: str | None = Query(None),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    session: SessionData = Depends(requires(Capability.VIEW_DASHBOARD)),
    db: AsyncSession = Depends(get_session),
) -> SlaPanel:
    start, end = _window(since, until)

    decided_stmt = (
        select(Finding, Assessment)
        .join(Assessment, Finding.assessment_id == Assessment.id)
        .where(
            Finding.decided_at.is_not(None), Finding.decided_at >= start, Finding.decided_at <= end
        )
    )
    if application_id:
        decided_stmt = decided_stmt.where(Assessment.application_id == application_id)
    decided_rows = (await db.execute(decided_stmt)).all()

    durations: list[float] = []
    for finding, assessment in decided_rows:
        assert finding.decided_at is not None  # filtered above
        reference = assessment.submitted_at or assessment.created_at
        durations.append((finding.decided_at - reference).total_seconds() / 3600.0)
    durations.sort()

    open_stmt = (
        select(Finding, Assessment)
        .join(Assessment, Finding.assessment_id == Assessment.id)
        .where(Finding.outcome == FindingOutcome.NEEDS_REVIEW)
    )
    if application_id:
        open_stmt = open_stmt.where(Assessment.application_id == application_id)
    open_rows = (await db.execute(open_stmt)).all()

    now = datetime.now(UTC)
    breaching = sum(
        1
        for _finding, assessment in open_rows
        if (now - (assessment.submitted_at or assessment.created_at)).total_seconds() / 3600.0
        > SLA_HOURS
    )

    return SlaPanel(
        since=start,
        until=end,
        median_hours_to_determination=_percentile(durations, 50),
        p90_hours_to_determination=_percentile(durations, 90),
        sample_size=len(durations),
        breaching_count=breaching,
    )


@router.get("/agreement", response_model=AgreementPanel)
async def agreement(
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    session: SessionData = Depends(requires(Capability.VIEW_DASHBOARD)),
    db: AsyncSession = Depends(get_session),
) -> AgreementPanel:
    start, end = _window(since, until)
    configs = {c.rule_id: c for c in (await db.execute(select(RuleConfig))).scalars()}

    rules_out: list[RuleAgreementOut] = []
    for rule in ACTIVE_RULES:
        if rule.tier is EvidenceTier.ESCALATION:
            # "Agreement" is meaningful only for a rule that can propose a
            # clear — see app.api.admin.compute_rule_agreement's docstring.
            continue
        result = await compute_rule_agreement(db, rule.id, since=start)
        cfg = configs.get(rule.id)
        bar = cfg.agreement_bar if cfg is not None else None
        below_bar = (
            bar is not None and result.agreement_rate is not None and result.agreement_rate < bar
        )
        rules_out.append(
            RuleAgreementOut(
                rule_id=rule.id,
                tier=rule.tier,
                agreement_rate=result.agreement_rate,
                agreement_bar=bar,
                below_bar=below_bar,
                volume_30d=result.volume_30d,
            )
        )

    return AgreementPanel(since=start, until=end, rules=rules_out)


@router.get("/outcome-mix", response_model=OutcomeMixPanel)
async def outcome_mix(
    application_id: str | None = Query(None),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    session: SessionData = Depends(requires(Capability.VIEW_DASHBOARD)),
    db: AsyncSession = Depends(get_session),
) -> OutcomeMixPanel:
    start, end = _window(since, until)
    outcomes = (
        FindingOutcome.NOT_AFFECTED,
        FindingOutcome.AFFECTED,
        FindingOutcome.RISK_ACCEPTANCE_REQUIRED,
    )
    stmt = (
        select(Finding, Assessment)
        .join(Assessment, Finding.assessment_id == Assessment.id)
        .where(
            Finding.decided_at.is_not(None),
            Finding.decided_at >= start,
            Finding.decided_at <= end,
            Finding.outcome.in_(outcomes),
        )
    )
    if application_id:
        stmt = stmt.where(Assessment.application_id == application_id)
    rows = (await db.execute(stmt)).all()

    by_app: dict[str, dict[str, int]] = {}
    for finding, assessment in rows:
        bucket = by_app.setdefault(
            assessment.application_id,
            {"not_affected": 0, "affected": 0, "risk_acceptance_required": 0},
        )
        assert finding.outcome is not None  # filtered above
        bucket[finding.outcome.value] += 1

    return OutcomeMixPanel(
        since=start,
        until=end,
        by_application=[
            OutcomeMixRow(application_id=app_id, **counts)
            for app_id, counts in sorted(by_app.items())
        ],
    )


@router.get("/expiry", response_model=ExpiryPanel)
async def expiry(
    application_id: str | None = Query(None),
    session: SessionData = Depends(requires(Capability.VIEW_DASHBOARD)),
    db: AsyncSession = Depends(get_session),
) -> ExpiryPanel:
    stmt = select(Assessment).where(Assessment.expires_at.is_not(None))
    if application_id:
        stmt = stmt.where(Assessment.application_id == application_id)
    assessments = (await db.execute(stmt)).scalars().all()

    now = datetime.now(UTC)
    horizon = now + _EXPIRY_LOOKAHEAD
    lapsing = 0
    expired = 0
    for a in assessments:
        assert a.expires_at is not None  # filtered above
        if a.expires_at < now:
            expired += 1
        elif a.expires_at <= horizon:
            lapsing += 1

    return ExpiryPanel(lapsing_within_7_days=lapsing, already_expired=expired)


__all__ = ["router"]
