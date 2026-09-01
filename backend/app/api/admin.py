"""Admin endpoints — [9] Rules & Thresholds.

``GET /api/admin/rules`` shows both ``app.rules.registry.ACTIVE_RULES`` (the
rules that actually run) and ``PENDING_EVIDENCE`` (rules that are written,
tested, and deliberately unregistered because their evidence source does not
exist yet) — see ``app/rules/registry.py``'s own docstring. An admin seeing
seven rules when ten exist in the codebase would otherwise reasonably assume
three are missing rather than deliberately withheld.

``PUT /api/admin/rules/{rule_id}`` writes to a new ``rule_config`` table
(migration ``0003``) — the existing eight-table schema had nowhere to persist
"is this rule allowed to auto-determine" or "what EPSS value hard-blocks",
even though ``app/config.py``'s own module docstring says exactly these
tunables belong in the database, not the environment, "because they are
decisions the team makes and must be audited." Flagged in the Task 4-6
report as a genuine no-data-source gap this task closed.

**A Tier 3 rule can never be given a toggle, including by constructing the
request directly.** ``update_rule`` checks the rule's own tier from the
registry — never trusts anything about tier from the request body — and
refuses ``auto_determination_enabled`` for any rule id that either is not a
registered Tier 1/2 rule at all, or is Tier 3. This is enforced independent
of whatever ``GET`` happens to render, so a client that never even looked at
the list response still cannot smuggle a toggle through.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import requires
from app.db import get_session
from app.domain.determination import EvidenceTier
from app.middleware.session import SessionData
from app.repos.models import AuditEntry, Finding, FindingOutcome, RuleConfig, RuleResult
from app.rules.engine import RuleVerdict
from app.rules.registry import ACTIVE_RULES, PENDING_EVIDENCE
from app.schemas.admin import (
    EscalationRuleOut,
    PendingRuleOut,
    RuleUpdateRequest,
    RuleUpdateResult,
    ToggleableRuleOut,
)
from app.services.authorization import Capability

router = APIRouter(prefix="/api/admin", tags=["admin"])

_LOOKBACK = timedelta(days=30)
_DEFAULT_EPSS_HARD_BLOCK = 0.10  # app.rules.engine.RuleEngine's own default.


def _is_rule_id(candidate: str) -> bool:
    """Whether ``candidate`` names an actual rule, as opposed to
    ``PENDING_EVIDENCE``'s one non-rule entry
    (``"tier3signals.reachable_with_call_path"`` — see
    ``app/rules/registry.py``'s own docstring on why that key is listed
    there at all).
    """
    prefix, _, rest = candidate.partition("-")
    return prefix in {"t1", "t2", "t3"} and bool(rest)


@dataclass(frozen=True, slots=True)
class RuleAgreement:
    """Where the rule's own SATISFIED-and-clearing result matched the
    finding's eventual outcome, over the lookback window — "the trust
    metric" (``docs/design/ui-spec.md`` dashboard panel 4).
    """

    agreement_rate: float | None
    volume_30d: int


async def compute_rule_agreement(
    db: AsyncSession, rule_id: str, *, since: datetime
) -> RuleAgreement:
    """Shared by ``GET /api/admin/rules`` and the dashboard's per-rule
    agreement panel (``app/api/dashboard.py``) so the two numbers can never
    drift from computing the same thing two different ways.

    ``volume_30d`` counts every persisted result for this rule in the
    window, regardless of verdict — "volume" per the ui-spec. Agreement is
    computed only over the subset that actually proposed a clear
    (SATISFIED, non-ESCALATION tier): a Tier 3 rule's SATISFIED (e.g. "EPSS
    is elevated") does not propose a direction an "agreement" comparison
    could ever match or mismatch against, so it is excluded rather than
    silently scored against the wrong question.
    """
    rows = (
        await db.execute(
            select(RuleResult, Finding)
            .join(Finding, RuleResult.finding_id == Finding.id)
            .where(RuleResult.rule_id == rule_id, Finding.decided_at >= since)
        )
    ).all()
    volume = len(rows)
    clearing = [
        (result, finding)
        for result, finding in rows
        if result.tier is not EvidenceTier.ESCALATION
        and (result.detail_json or {}).get("rule_verdict") == RuleVerdict.SATISFIED.value
    ]
    if not clearing:
        return RuleAgreement(agreement_rate=None, volume_30d=volume)
    agreed = sum(1 for _, finding in clearing if finding.outcome is FindingOutcome.NOT_AFFECTED)
    return RuleAgreement(agreement_rate=agreed / len(clearing), volume_30d=volume)


async def _epss_routing_difference(
    db: AsyncSession, *, old_threshold: float, new_threshold: float, since: datetime
) -> int:
    """How many of the last 30 days' findings with a recorded EPSS value
    would have hit the hard blocker differently under ``new_threshold`` —
    the blast-radius preview the task-6 brief requires before saving.
    """
    rows = (
        (
            await db.execute(
                select(RuleResult)
                .join(Finding, RuleResult.finding_id == Finding.id)
                .where(RuleResult.rule_id == "t3-epss", Finding.decided_at >= since)
            )
        )
        .scalars()
        .all()
    )
    count = 0
    for row in rows:
        epss = (row.detail_json or {}).get("epss")
        if epss is None:
            continue
        if (epss >= old_threshold) != (epss >= new_threshold):
            count += 1
    return count


@router.get("/rules", response_model=list[ToggleableRuleOut | EscalationRuleOut | PendingRuleOut])
async def list_rules(
    session: SessionData = Depends(requires(Capability.MANAGE_RULES)),
    db: AsyncSession = Depends(get_session),
) -> list[ToggleableRuleOut | EscalationRuleOut | PendingRuleOut]:
    since = datetime.now(UTC) - _LOOKBACK
    configs = {c.rule_id: c for c in (await db.execute(select(RuleConfig))).scalars()}

    out: list[ToggleableRuleOut | EscalationRuleOut | PendingRuleOut] = []
    for rule in ACTIVE_RULES:
        cfg = configs.get(rule.id)
        agreement = await compute_rule_agreement(db, rule.id, since=since)
        thresholds = dict(cfg.thresholds_json) if cfg is not None else {}
        if rule.tier is EvidenceTier.ESCALATION:
            out.append(
                EscalationRuleOut(
                    rule_id=rule.id,
                    tier=rule.tier,
                    version=rule.version,
                    volume_30d=agreement.volume_30d,
                    thresholds=thresholds,
                )
            )
        else:
            enabled = cfg.auto_determination_enabled if cfg is not None else True
            bar = cfg.agreement_bar if cfg is not None else None
            auto_suspended = (
                bar is not None
                and agreement.agreement_rate is not None
                and agreement.agreement_rate < bar
            )
            out.append(
                ToggleableRuleOut(
                    rule_id=rule.id,
                    tier=rule.tier,
                    version=rule.version,
                    auto_determination_enabled=enabled,
                    agreement_bar=bar,
                    agreement_rate=agreement.agreement_rate,
                    auto_suspended=auto_suspended,
                    volume_30d=agreement.volume_30d,
                    thresholds=thresholds,
                )
            )

    for rule_id, reason in PENDING_EVIDENCE.items():
        if _is_rule_id(rule_id):
            out.append(PendingRuleOut(rule_id=rule_id, reason=reason))

    return out


@router.put("/rules/{rule_id}", response_model=RuleUpdateResult)
async def update_rule(
    rule_id: str,
    body: RuleUpdateRequest,
    session: SessionData = Depends(requires(Capability.MANAGE_RULES)),
    db: AsyncSession = Depends(get_session),
) -> RuleUpdateResult:
    rule = next((r for r in ACTIVE_RULES if r.id == rule_id), None)
    if rule is None and rule_id not in PENDING_EVIDENCE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"unknown rule id: {rule_id!r}"
        )

    if body.auto_determination_enabled is not None and (
        rule is None or rule.tier is EvidenceTier.ESCALATION
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"{rule_id!r} has no auto-determination toggle: Tier 3 (escalation) evidence "
                "can never auto-determine a clear, and a pending-evidence rule is not "
                "registered to run at all"
            ),
        )
    if body.epss_hard_block_threshold is not None and rule_id != "t3-epss":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="epss_hard_block_threshold only applies to the t3-epss rule",
        )

    cfg = await db.get(RuleConfig, rule_id)
    if cfg is None:
        cfg = RuleConfig(rule_id=rule_id)
        db.add(cfg)

    now = datetime.now(UTC)
    routing_difference_count: int | None = None

    if body.auto_determination_enabled is not None:
        cfg.auto_determination_enabled = body.auto_determination_enabled
    if body.agreement_bar is not None:
        cfg.agreement_bar = body.agreement_bar
    if body.epss_hard_block_threshold is not None:
        old_threshold = cfg.thresholds_json.get("hard_block_threshold", _DEFAULT_EPSS_HARD_BLOCK)
        routing_difference_count = await _epss_routing_difference(
            db,
            old_threshold=old_threshold,
            new_threshold=body.epss_hard_block_threshold,
            since=now - _LOOKBACK,
        )
        cfg.thresholds_json = {
            **cfg.thresholds_json,
            "hard_block_threshold": body.epss_hard_block_threshold,
        }

    cfg.updated_at = now
    cfg.updated_by = session.username

    db.add(
        AuditEntry(
            actor=session.username,
            action="admin.rule_updated",
            subject_type="rule",
            subject_id=rule_id,
            detail_json={
                "auto_determination_enabled": body.auto_determination_enabled,
                "agreement_bar": body.agreement_bar,
                "epss_hard_block_threshold": body.epss_hard_block_threshold,
                "routing_difference_count": routing_difference_count,
            },
            created_at=now,
        )
    )
    await db.commit()

    is_toggleable = rule is not None and rule.tier is not EvidenceTier.ESCALATION
    out_enabled = cfg.auto_determination_enabled if is_toggleable else None
    return RuleUpdateResult(
        rule_id=rule_id,
        auto_determination_enabled=out_enabled,
        agreement_bar=cfg.agreement_bar,
        epss_hard_block_threshold=cfg.thresholds_json.get("hard_block_threshold"),
        routing_difference_count=routing_difference_count,
        updated_by=session.username,
        updated_at=now,
    )


__all__ = ["compute_rule_agreement", "router"]
