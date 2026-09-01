"""Request/response shapes for ``app/api/admin.py`` — [9] Rules & Thresholds.

**A Tier 3 rule's shape has no ``auto_determination_enabled`` field at
all — not a ``null``, the key itself is absent from the JSON.** Modelled as
two distinct response shapes (:class:`ToggleableRuleOut`,
:class:`EscalationRuleOut`) rather than one shape with an optional field, so
"this rule has no toggle" is a fact about the wire format itself, not
something a frontend has to remember to check a boolean for. See
``docs/design/ui-spec.md`` screen 9: "A Tier 3 rule has no auto-determination
toggle. Not disabled — absent, because the capability does not exist.
Rendering a greyed-out toggle implies it could be turned on."
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.domain.determination import EvidenceTier


class ToggleableRuleOut(BaseModel):
    """A Tier 1 or Tier 2 rule — the only rules that may ever auto-determine
    a clear, and so the only ones with a toggle at all."""

    rule_id: str
    tier: EvidenceTier
    version: str
    has_auto_determination_toggle: Literal[True] = True
    auto_determination_enabled: bool
    agreement_bar: float | None
    agreement_rate: float | None
    #: True when ``agreement_rate`` is known and falls below ``agreement_bar``
    #: — "shows as auto-suspended, with the reason" (ui-spec screen 9).
    auto_suspended: bool
    volume_30d: int
    thresholds: dict[str, float] = Field(default_factory=dict)


class EscalationRuleOut(BaseModel):
    """A Tier 3 (ESCALATION) rule. Never carries
    ``auto_determination_enabled`` — see this module's docstring."""

    rule_id: str
    tier: EvidenceTier
    version: str
    has_auto_determination_toggle: Literal[False] = False
    volume_30d: int
    thresholds: dict[str, float] = Field(default_factory=dict)


class PendingRuleOut(BaseModel):
    """A rule id from ``app.rules.registry.PENDING_EVIDENCE`` — written,
    tested, and deliberately not registered because its evidence source
    does not exist yet. Shown so an admin sees exactly how many rules are
    deliberately unregistered, rather than assuming they are missing."""

    rule_id: str
    registered: Literal[False] = False
    reason: str


class RuleUpdateRequest(BaseModel):
    """A change to one rule's configuration. Every field is optional — only
    the fields supplied are changed; omitted fields are left as they are.

    ``auto_determination_enabled`` is refused (422) for a Tier 3 rule id, or
    for any rule id unknown to the registry — including by constructing the
    request directly against a Tier 3 rule id, never only by what a
    well-behaved client would send. See ``app/api/admin.py``'s
    ``update_rule``.
    """

    auto_determination_enabled: bool | None = None
    agreement_bar: float | None = None
    #: Only meaningful for ``t3-epss`` — the EPSS probability at/above which
    #: ``RuleEngine``'s hard blocker fires (``docs/design/ui-mockups.html``'s
    #: "EPSS routing threshold" admin field). Refused for any other rule id.
    epss_hard_block_threshold: float | None = None


class RuleUpdateResult(BaseModel):
    rule_id: str
    auto_determination_enabled: bool | None
    agreement_bar: float | None
    epss_hard_block_threshold: float | None
    #: How many of the last 30 days' findings with a recorded EPSS value
    #: would have hit the hard blocker differently under the new threshold —
    #: "shows how many of the last 30 days' findings would have been routed
    #: differently, before saving" (task-6 brief). ``None`` when this update
    #: did not change a threshold (nothing to preview).
    routing_difference_count: int | None
    updated_by: str
    updated_at: datetime


__all__ = [
    "EscalationRuleOut",
    "PendingRuleOut",
    "RuleUpdateRequest",
    "RuleUpdateResult",
    "ToggleableRuleOut",
]
