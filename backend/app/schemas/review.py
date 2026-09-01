"""Request/response shapes for ``app/api/review.py``.

Serves [5] Review Queue, [6] Assessment Detail (the same table, scoped by
``assessment_id``) and the Evidence Drawer overlay (``docs/design/ui-spec.md``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.domain.determination import Confidence, EvidenceTier, Justification
from app.repos.models import FindingOutcome
from app.schemas.common import AiVerdictOut, EscalationSignals, RuleTraceEntry

#: Fixed SLA policy: hours from an assessment's submission before a
#: NEEDS_REVIEW finding is considered overdue. No admin control for this
#: exists anywhere in the persisted schema (``rule_config`` covers rule
#: toggles/thresholds, not a queue SLA) — flagged in the task report as a
#: scoped-down default rather than a genuine "no data source" gap, since
#: nothing downstream depends on this number being correct, only display.
SLA_HOURS = 24.0
#: Below this many hours remaining, a finding is "urgent" rather than "ok".
SLA_URGENT_HOURS = 4.0

SlaBand = Literal["breaching", "urgent", "ok", "n/a"]


class ReviewFindingRow(BaseModel):
    """One row in the queue table — [5] Review Queue's columns."""

    id: str
    assessment_id: str
    application_id: str
    cve: str
    purl: str
    outcome: FindingOutcome
    #: The best-known proposed outcome for this finding today — for a
    #: decided finding, this is just its own outcome; for one still
    #: NEEDS_REVIEW, this is the same value ("needs review"), matching
    #: ``docs/design/ui-spec.md``'s mockup literally (every row, decided or
    #: not, shows a RECOMMENDED value). A human reviewer's own proposal,
    #: recorded via ``POST .../recommend``, is advisory and does not change
    #: this field — see ``app/api/review.py``'s module docstring.
    recommended_outcome: FindingOutcome
    tier: EvidenceTier | None
    justification: Justification | None
    confidence: Confidence | None
    sla_band: SlaBand
    sla_hours_remaining: float | None
    age_hours: float
    requester: str
    decided_by: str | None
    decided_at: datetime | None


class RecommendationOut(BaseModel):
    """The Evidence Drawer's "RECOMMENDATION" section — the proposed outcome
    and a plain-language reason, never a bare enum."""

    outcome: FindingOutcome
    reason: str
    tier: EvidenceTier | None
    justification: Justification | None
    confidence: Confidence | None
    requires_second_confirmation: bool


class DeterminationOut(BaseModel):
    """The committed determination, when this finding already has one."""

    tier: EvidenceTier
    justification: Justification
    confidence: Confidence
    evidence_refs: list[str]
    decided_by: str
    decided_at: datetime
    #: Whether committing this created a Nexus IQ suppression — always True
    #: for a committed NOT_AFFECTED (the only state that ever does).
    iq_suppressed: bool


class ReviewFindingDetail(BaseModel):
    """The Evidence Drawer's full payload for one finding.

    **Escalation signals are their own field, structurally apart from
    ``rule_trace`` and ``recommendation`` — see ``app.schemas.common``'s
    module docstring.** Nothing about a Not Affected recommendation is ever
    computed from, or rendered next to, ``escalation`` in this shape.
    """

    id: str
    assessment_id: str
    application_id: str
    cve: str
    purl: str
    threat_level: int | None
    outcome: FindingOutcome
    recommendation: RecommendationOut
    rule_trace: list[RuleTraceEntry]
    escalation: EscalationSignals
    ai_verdict: AiVerdictOut | None
    missing_evidence: list[str] = Field(default_factory=list)
    determination: DeterminationOut | None = None


class RecommendRequest(BaseModel):
    """A reviewer's (non-binding) proposal — recorded as an audit entry,
    never a route around ``commit_determination``. See
    ``app/api/review.py``'s module docstring.
    """

    outcome: Literal["not_affected", "affected", "needs_review"]
    justification: Justification | None = None
    note: str | None = None


class RecommendationRecorded(BaseModel):
    finding_id: str
    outcome: str
    recorded_by: str
    recorded_at: datetime


class DecideRequest(BaseModel):
    """An approver's commit action (``POST .../decide``).

    **There is no ``tier`` field.** The mockup's Determination controls
    (``docs/design/ui-spec.md``'s Evidence Drawer) never let a reviewer pick
    a tier — "A cleared verdict always shows its tier" is read-only display,
    derived from the achieved evidence, not an input. ``app/api/review.py``
    derives the tier itself from the finding's own persisted rule trace/AI
    verdict (the strongest — lowest — tier with a SATISFIED clearing result)
    and refuses the commit if no PROOF or STRONG evidence exists to support
    ``justification`` at all; an approver cannot assert a tier the evidence
    never achieved.

    ``second_confirmer`` is required, and must name someone other than the
    committing approver, whenever the *derived* tier is STRONG (Tier 2) —
    defeasible evidence needs an independent second confirmation before it
    may clear a finding (docs/design.md;
    ``EvidenceTier.requires_second_confirmation``). Only
    ``not_affected``/``affected`` are accepted here: "commits" means a
    terminal outcome, never ``needs_review`` (leaving a finding in the queue
    needs no API call) and never ``risk_acceptance_required`` (assigned only
    by the automated pipeline when no fix exists — CLAUDE.md rule 5 — never
    a human's choice to make).
    """

    outcome: Literal["not_affected", "affected"]
    justification: Justification | None = None
    note: str | None = None
    second_confirmer: str | None = None


__all__ = [
    "SLA_HOURS",
    "SLA_URGENT_HOURS",
    "DecideRequest",
    "DeterminationOut",
    "RecommendRequest",
    "RecommendationOut",
    "RecommendationRecorded",
    "ReviewFindingDetail",
    "ReviewFindingRow",
    "SlaBand",
]
