"""Risk acceptance endpoints — [8] Risk Acceptance Queue.

Every row here is a hand-off, not a determination — see
``app.schemas.risk``'s module docstring. ``PUT .../status`` requires
``MANAGE_RISK_ACCEPTANCE`` (risk manager only), distinct from
``VIEW_RISK_ACCEPTANCE`` (risk manager and auditor) — an auditor can watch
this queue but must never be able to write to it, per
``app/services/authorization.py``'s own module docstring on why the call
site checks a capability, never a role.

``GET .../package`` reuses ``app.api.review.build_finding_detail`` rather
than reassembling the rule trace/escalation signals a second time — the
"evidence package" is the same underlying evidence a reviewer would see in
the drawer, wrapped as a self-contained downloadable document plus the
assessment/application header a stand-alone document needs that the drawer
gets for free from its surrounding screen.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import requires
from app.api.review import build_finding_detail
from app.db import get_session
from app.middleware.session import SessionData
from app.repos.models import Assessment, AuditEntry, Finding, FindingOutcome
from app.schemas.common import plain_language_reason
from app.schemas.risk import HandoffStatus, HandoffStatusUpdate, RiskAcceptanceRow
from app.services.authorization import Capability

router = APIRouter(prefix="/api/risk-acceptance", tags=["risk-acceptance"])

_STATUS_ACTION = "risk_acceptance.status_changed"
_DEFAULT_STATUS: HandoffStatus = "awaiting_hand_off"


async def _load(db: AsyncSession, finding_id: str) -> tuple[Finding, Assessment]:
    finding = await db.get(Finding, finding_id)
    if finding is None or finding.outcome is not FindingOutcome.RISK_ACCEPTANCE_REQUIRED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no risk-acceptance finding with that id",
        )
    assessment = await db.get(Assessment, finding.assessment_id)
    assert assessment is not None
    return finding, assessment


async def _latest_status(
    db: AsyncSession, finding_id: str
) -> tuple[HandoffStatus, str | None, datetime | None]:
    result = await db.execute(
        select(AuditEntry)
        .where(
            AuditEntry.subject_type == "finding",
            AuditEntry.subject_id == finding_id,
            AuditEntry.action == _STATUS_ACTION,
        )
        .order_by(AuditEntry.created_at.desc())
        .limit(1)
    )
    entry = result.scalars().first()
    if entry is None or entry.detail_json is None:
        return _DEFAULT_STATUS, None, None
    return entry.detail_json["status"], entry.actor, entry.created_at


async def _affected_applications_count(db: AsyncSession, cve: str) -> int:
    result = await db.execute(
        select(Assessment.application_id)
        .join(Finding, Finding.assessment_id == Assessment.id)
        .where(Finding.cve == cve)
        .distinct()
    )
    return len(result.all())


def _age_hours(assessment: Assessment) -> float:
    reference = assessment.submitted_at or assessment.created_at
    return (datetime.now(UTC) - reference).total_seconds() / 3600.0


async def _row_out(db: AsyncSession, finding: Finding, assessment: Assessment) -> RiskAcceptanceRow:
    detail = await build_finding_detail(db, finding, assessment)
    status_value, status_by, status_at = await _latest_status(db, finding.id)
    affected = await _affected_applications_count(db, finding.cve)
    reason = plain_language_reason(
        outcome=FindingOutcome.RISK_ACCEPTANCE_REQUIRED,
        tier=None,
        justification=None,
        blocked_by=set(),
        missing_evidence=[],
    )
    return RiskAcceptanceRow(
        finding_id=finding.id,
        assessment_id=assessment.id,
        application_id=assessment.application_id,
        cve=finding.cve,
        purl=finding.purl,
        reason=reason,
        escalation=detail.escalation,
        affected_applications_count=affected,
        age_hours=_age_hours(assessment),
        status=status_value,
        status_updated_by=status_by,
        status_updated_at=status_at,
    )


@router.get("", response_model=list[RiskAcceptanceRow])
async def list_risk_acceptance(
    session: SessionData = Depends(requires(Capability.VIEW_RISK_ACCEPTANCE)),
    db: AsyncSession = Depends(get_session),
) -> list[RiskAcceptanceRow]:
    """Only ``RISK_ACCEPTANCE_REQUIRED`` findings — nothing else ever
    appears in this queue, which is the whole point of the outcome existing
    at all (CLAUDE.md rule 5).
    """
    findings = (
        (
            await db.execute(
                select(Finding, Assessment)
                .join(Assessment, Finding.assessment_id == Assessment.id)
                .where(Finding.outcome == FindingOutcome.RISK_ACCEPTANCE_REQUIRED)
            )
        )
        .all()
    )
    return [await _row_out(db, finding, assessment) for finding, assessment in findings]


@router.put("/{finding_id}/status", response_model=RiskAcceptanceRow)
async def update_status(
    finding_id: str,
    body: HandoffStatusUpdate,
    session: SessionData = Depends(requires(Capability.MANAGE_RISK_ACCEPTANCE)),
    db: AsyncSession = Depends(get_session),
) -> RiskAcceptanceRow:
    """Manually set by the risk manager. The portal only records this — it
    never enforces or acts on it (``docs/design/ui-spec.md`` screen 8).
    """
    finding, assessment = await _load(db, finding_id)
    now = datetime.now(UTC)
    db.add(
        AuditEntry(
            actor=session.username,
            action=_STATUS_ACTION,
            subject_type="finding",
            subject_id=finding.id,
            detail_json={"status": body.status},
            created_at=now,
        )
    )
    await db.commit()
    return await _row_out(db, finding, assessment)


@router.get("/{finding_id}/package")
async def download_package(
    finding_id: str,
    session: SessionData = Depends(requires(Capability.VIEW_RISK_ACCEPTANCE)),
    db: AsyncSession = Depends(get_session),
) -> Response:
    """A self-contained evidence document the app team takes to their risk
    manager. No GRC integration — this is a deliberate hand-off, tracked
    only to the point of leaving the portal (``docs/design/ui-spec.md``).
    """
    finding, assessment = await _load(db, finding_id)
    detail = await build_finding_detail(db, finding, assessment)
    status_value, status_by, status_at = await _latest_status(db, finding.id)

    package = {
        "generated_at": datetime.now(UTC).isoformat(),
        "application_id": assessment.application_id,
        "assessment_id": assessment.id,
        "report_id": assessment.report_id,
        "requester": assessment.requester,
        "cve": finding.cve,
        "component": finding.purl,
        "reason": plain_language_reason(
            outcome=FindingOutcome.RISK_ACCEPTANCE_REQUIRED,
            tier=None,
            justification=None,
            blocked_by=set(),
            missing_evidence=[],
        ),
        "escalation_signals": detail.escalation.model_dump(),
        "rule_trace": [entry.model_dump() for entry in detail.rule_trace],
        "hand_off_status": {
            "status": status_value,
            "set_by": status_by,
            "set_at": status_at.isoformat() if status_at else None,
        },
        "note": (
            "This is a hand-off, not a determination. No fix is currently available for "
            "this vulnerability; the Nexus IQ violation remains open. The portal does not "
            "enforce whatever your risk manager decides."
        ),
    }
    body = json.dumps(package, indent=2, default=str)
    filename = f"risk-acceptance-{finding.cve}-{finding.id}.json"
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


__all__ = ["router"]
