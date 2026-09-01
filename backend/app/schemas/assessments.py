"""Request/response shapes for ``app/api/assessments.py``.

Serves three screens (``docs/design/ui-spec.md``): [2] New Assessment (the
raise request), [3] My Assessments (:class:`AssessmentSummary`, a list of
assessment-level rows, not findings), and [4] Assessment Result
(:class:`AssessmentDetail`, read-only per-finding detail for the requester).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.domain.determination import Confidence, EvidenceTier, Justification
from app.repos.models import AssessmentState, FindingOutcome
from app.schemas.common import OutcomeCounts


class RaiseAssessmentRequest(BaseModel):
    """[2] New Assessment's submit body.

    ``requester_note`` is the form's "Why is this needed?" free text — see
    ``app.repos.models.Assessment.requester_note``'s own docstring: reviewer
    context only, never a VEX justification, and never read by the rule
    engine.
    """

    application_id: str = Field(min_length=1)
    report_id: str = Field(min_length=1)
    artifact_coordinates: str = Field(min_length=1)
    commit_sha: str | None = None
    requester_note: str = Field(min_length=1)


class AdmissionFailureOut(BaseModel):
    """Which of the three admission checks failed, and what to do about it —
    ``docs/design/ui-spec.md``'s admission-checks table: "Fail message must
    say..." for each of the three checks.
    """

    check: Literal["report", "artifact", "provenance"]
    message: str


class FindingOut(BaseModel):
    """One finding, at the detail a requester (screen 4) needs: outcome and
    the reason in plain language, never the reviewer's full rule
    trace/escalation-signal breakdown (``app/api/review.py`` owns that,
    scoped to reviewers/approvers).
    """

    id: str
    cve: str
    purl: str
    outcome: FindingOutcome | None
    reason: str
    tier: EvidenceTier | None
    justification: Justification | None
    confidence: Confidence | None
    evidence_refs: list[str] = Field(default_factory=list)
    decided_at: datetime | None


class AssessmentSummary(BaseModel):
    """One row on [3] My Assessments — assessment-level, not finding-level."""

    id: str
    application_id: str
    report_id: str
    state: AssessmentState
    requester: str
    requester_note: str | None
    finding_count: int
    outcome_counts: OutcomeCounts
    created_at: datetime
    submitted_at: datetime | None
    expires_at: datetime | None
    admission_failure: AdmissionFailureOut | None = None


class AssessmentDetail(BaseModel):
    """[4] Assessment Result: the assessment header plus every finding."""

    id: str
    application_id: str
    report_id: str
    state: AssessmentState
    requester: str
    requester_note: str | None
    commit_sha: str | None
    artifact_ref: str | None
    created_at: datetime
    submitted_at: datetime | None
    expires_at: datetime | None
    admission_failure: AdmissionFailureOut | None = None
    #: The provenance fingerprint snapshot (``app.evidence.pack.EvidencePack.provenance``),
    #: as persisted by ``app.services.collection``'s snapshot step — "provenance
    #: ✓ 118/118 components matched" in ``docs/design/ui-spec.md`` screen 6's
    #: header. ``None`` only when analysis has not run yet (e.g. admission failed).
    provenance: dict[str, object] | None = None
    outcome_counts: OutcomeCounts
    findings: list[FindingOut]


class ApplicationOut(BaseModel):
    """One row in [2] New Assessment's application select — scoped to the
    caller's own Nexus IQ entitlement (``IqClient.applications_for_user``).
    """

    id: str
    name: str


__all__ = [
    "AdmissionFailureOut",
    "ApplicationOut",
    "AssessmentDetail",
    "AssessmentSummary",
    "FindingOut",
    "RaiseAssessmentRequest",
]
