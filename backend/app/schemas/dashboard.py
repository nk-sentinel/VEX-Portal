"""Request/response shapes for ``app/api/dashboard.py`` — [7] Dashboard.

One model per panel (``docs/design/ui-spec.md`` names six), matching one
route per panel: "one failed panel must not blank the page" is far easier to
guarantee client-side when each panel is its own request than when one
combined call can partially fail.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domain.determination import EvidenceTier


class VolumePanel(BaseModel):
    since: datetime
    until: datetime
    total_assessments: int
    total_findings: int
    #: Outcome value -> count. A finding not yet decided (still
    #: ``NEEDS_REVIEW`` or, in principle, never processed) is bucketed
    #: under ``"needs_review"`` like any other outcome — there is no
    #: separate "undetermined" bucket to hide behind.
    findings_by_outcome: dict[str, int] = Field(default_factory=dict)


class AutomationSplitPanel(BaseModel):
    """"The headline number for whether the portal is working" — ui-spec."""

    since: datetime
    until: datetime
    total_decided: int
    automated: int
    human_reviewed: int
    automated_ratio: float | None


class SlaPanel(BaseModel):
    since: datetime
    until: datetime
    median_hours_to_determination: float | None
    p90_hours_to_determination: float | None
    sample_size: int
    #: A live count, not windowed by ``since``/``until`` — how many
    #: NEEDS_REVIEW findings are, right now, past the SLA policy window
    #: (``app.schemas.review.SLA_HOURS``).
    breaching_count: int


class RuleAgreementOut(BaseModel):
    rule_id: str
    tier: EvidenceTier
    agreement_rate: float | None
    agreement_bar: float | None
    below_bar: bool
    volume_30d: int


class AgreementPanel(BaseModel):
    """"The trust metric" (ui-spec) — per-rule, not scoped by application:
    a rule's trustworthiness is a portal-wide fact about the rule, not
    something that varies by which application a finding belongs to.
    """

    since: datetime
    until: datetime
    rules: list[RuleAgreementOut] = Field(default_factory=list)


class OutcomeMixRow(BaseModel):
    application_id: str
    not_affected: int
    affected: int
    risk_acceptance_required: int


class OutcomeMixPanel(BaseModel):
    since: datetime
    until: datetime
    by_application: list[OutcomeMixRow] = Field(default_factory=list)


class ExpiryPanel(BaseModel):
    """"Incoming reassessment load" — ui-spec."""

    lapsing_within_7_days: int
    already_expired: int


__all__ = [
    "AgreementPanel",
    "AutomationSplitPanel",
    "ExpiryPanel",
    "OutcomeMixPanel",
    "RuleAgreementOut",
    "SlaPanel",
    "VolumePanel",
]
