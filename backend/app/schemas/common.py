"""Shapes shared by more than one screen's endpoints.

**Escalation signals live in their own model, with their own name, on
purpose.** ``docs/design/ui-spec.md``'s rule 0 says CVSS/EPSS/KEV/fix
availability "may explain why something was sent to a human, never why
something was cleared" and must never "render... adjacent to a Not Affected
verdict in a way that reads as supporting it." A flat response bag makes
that distinction something the UI has to remember on every screen; putting
these fields on :class:`EscalationSignals` — never merged into
:class:`RuleTraceEntry` or any clearing-evidence shape — makes rendering
them next to a clear an awkward, deliberate act (reach into a differently
named object) rather than the natural one (read the next field in the same
bag). See ``app/api/review.py`` for where this is assembled per finding.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.domain.determination import Confidence, EvidenceTier, Justification, State
from app.repos.models import FindingOutcome

#: The one line every screen that renders escalation signals must carry
#: alongside them, verbatim — see ``docs/design/ui-spec.md``'s "Escalation
#: signals carry no colour at all... a permanent 'not a basis for clearing'
#: line."
NOT_A_BASIS_NOTE = "not a basis for clearing"


class OutcomeCounts(BaseModel):
    """How many findings landed in each outcome, for one assessment or one
    filtered slice of the queue."""

    not_affected: int = 0
    affected: int = 0
    needs_review: int = 0
    risk_acceptance_required: int = 0

    @property
    def total(self) -> int:
        return self.not_affected + self.affected + self.needs_review + self.risk_acceptance_required


class EscalationSignals(BaseModel):
    """CVSS, EPSS, KEV and fix availability for one finding's CVE.

    Structurally separate from the rule trace — see this module's docstring.
    Every field is optional because every one of these is itself a
    tri-state "not looked up" fact (``app.rules.engine.Tier3Signals``'s own
    docstring); ``None`` here means the same thing it means there: unknown,
    never a coerced safe default.
    """

    epss: float | None = None
    kev: bool | None = None
    cvss_base_score: float | None = None
    cvss_vector: str | None = None
    fix_available: bool | None = None

    #: Which of these signals actually triggered routing to a human for
    #: *this* finding — a subset of {"kev", "reachable", "epss", "cvss"},
    #: taken verbatim from ``EngineOutcome.blocked_by`` at determination
    #: time. Empty does not mean "nothing here is concerning" — it means no
    #: *hard blocker* fired; a Tier 3 rule can still be SATISFIED (e.g. a
    #: notable but sub-hard-blocker CVSS shape) without blocking anything.
    hard_blockers: list[str] = Field(default_factory=list)

    note: str = NOT_A_BASIS_NOTE


class RuleTraceEntry(BaseModel):
    """One Tier 1/2 rule's result — the audit surface and reviewer's trust
    surface. Deliberately excludes Tier 3 (ESCALATION) rule results, which
    surface only through :class:`EscalationSignals` — see this module's
    docstring for why the two are never merged.
    """

    rule_id: str
    rule_version: str
    tier: EvidenceTier
    verdict: str
    justification: Justification | None
    detail: dict[str, object]


class AiVerdictOut(BaseModel):
    """One AI adjudicator pass, as the reviewer needs to see it."""

    model_id: str
    prompt_version: str
    state: State
    justification: Justification | None
    confidence: Confidence
    evidence_refs: list[str]
    missing_evidence: list[str]
    #: Set when an independent refute pass ran and agreed — required before
    #: a Tier 2/AI clear may auto-determine.
    refuted_by: str | None


def plain_language_reason(
    *,
    outcome: FindingOutcome | None,
    tier: EvidenceTier | None,
    justification: Justification | None,
    blocked_by: frozenset[str] | set[str],
    missing_evidence: list[str],
) -> str:
    """A human-readable sentence for one finding's outcome.

    **No natural-language explanation is persisted anywhere in this system**
    — ``app.repos.models.AiVerdict`` carries only closed enums
    (state/justification/confidence/evidence_refs/missing_evidence), never a
    free-text rationale, and the same is true of ``RuleResult``. The
    evidence-drawer mockup's prose ("the vulnerable class ships and nothing
    references it, but...") has no backing field anywhere reachable from the
    API — flagged in the task report as a finding with no data source. This
    function is a template over the structured facts that *are* persisted,
    not a retrieval of stored narrative text.
    """
    _JUSTIFICATION_TEXT = {
        Justification.CODE_NOT_PRESENT: "the vulnerable code does not ship in this artifact",
        Justification.CODE_NOT_REACHABLE: (
            "the vulnerable code ships but nothing in the application references it"
        ),
        Justification.REQUIRES_DEPENDENCY: (
            "exploitation requires a companion component that is not present"
        ),
        Justification.REQUIRES_CONFIGURATION: (
            "exploitation requires a configuration this application does not set, and the "
            "library default is safe"
        ),
        Justification.REQUIRES_ENVIRONMENT: (
            "the running environment falls outside the affected range"
        ),
        Justification.PROTECTED_AT_PERIMETER: "network controls prevent reach",
        Justification.PROTECTED_BY_MITIGATING_CONTROL: "a compensating control blocks exploitation",
    }

    if outcome is FindingOutcome.NOT_AFFECTED:
        basis = _JUSTIFICATION_TEXT.get(justification) if justification else None
        tier_label = tier.name.title() if tier is not None else "evidence"
        if basis:
            return f"Not affected ({tier_label} evidence): {basis}."
        return f"Not affected, based on {tier_label} evidence."

    if outcome is FindingOutcome.AFFECTED:
        return "This vulnerability applies. Remediation is required."

    if outcome is FindingOutcome.RISK_ACCEPTANCE_REQUIRED:
        return (
            "No fix is available. This did not receive a determination. Take the evidence "
            "package to your risk manager."
        )

    # NEEDS_REVIEW, or not yet decided at all.
    if blocked_by:
        signals = ", ".join(sorted(blocked_by))
        return f"Routed to a human reviewer: escalation signal(s) fired ({signals})."
    if missing_evidence:
        return (
            "Routed to a human reviewer: evidence was insufficient to determine either way "
            f"({'; '.join(missing_evidence)})."
        )
    return "Routed to a human reviewer: no rule or the adjudicator could conclusively clear it."


__all__ = [
    "NOT_A_BASIS_NOTE",
    "AiVerdictOut",
    "EscalationSignals",
    "OutcomeCounts",
    "RuleTraceEntry",
    "plain_language_reason",
]
