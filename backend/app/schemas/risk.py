"""Request/response shapes for ``app/api/risk.py`` — [8] Risk Acceptance
Queue.

Every row here is a ``RISK_ACCEPTANCE_REQUIRED`` finding: no fix exists, the
finding received no determination, and the Nexus IQ violation stays open
(CLAUDE.md rule 5). ``docs/design/ui-spec.md``: "These received no
determination and the IQ violation is still open. The screen must be
unambiguous about that" — reflected here by never including a
``DeterminationOut``-shaped field anywhere in this module: there is nothing
to show, on purpose.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas.common import EscalationSignals

#: Manually set by the risk manager; the portal never infers or enforces
#: this — see ``docs/design/ui-spec.md`` screen 8: "the screen states
#: plainly that the portal does not enforce the outcome."
HandoffStatus = Literal["awaiting_hand_off", "with_risk_manager", "accepted", "rejected"]


class RiskAcceptanceRow(BaseModel):
    finding_id: str
    assessment_id: str
    application_id: str
    cve: str
    purl: str
    #: Why no fix is available, in plain language — see
    #: ``app.schemas.common.plain_language_reason``.
    reason: str
    escalation: EscalationSignals
    #: How many *other* applications also carry a RISK_ACCEPTANCE_REQUIRED
    #: finding for this same CVE — "affected applications count" (ui-spec).
    affected_applications_count: int
    age_hours: float
    status: HandoffStatus
    status_updated_by: str | None
    status_updated_at: datetime | None


class HandoffStatusUpdate(BaseModel):
    status: HandoffStatus


__all__ = ["HandoffStatus", "HandoffStatusUpdate", "RiskAcceptanceRow"]
