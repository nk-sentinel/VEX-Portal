"""The vocabulary of the portal.

Terminology note: this portal never says "waiver". Audit and management read that
word as suppressing a real finding. What the portal records is a *determination*
that a vulnerability does not apply to an application. The Nexus IQ waiver is
only the enforcement mechanism behind a ``NOT_AFFECTED`` determination — an
implementation detail of the IQ adapter, never a concept surfaced in the UI,
notifications, or reports.

The vocabulary is CycloneDX VEX, so determinations are expressible in a standard
that auditors and downstream tooling already understand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class State(StrEnum):
    """The VEX analysis state of a determination."""

    #: The vulnerability is not exploitable in this application. This is the
    #: only state that results in an IQ waiver being created.
    NOT_AFFECTED = "not_affected"

    #: The vulnerability applies. Remediation is required; the portal never
    #: suppresses these.
    AFFECTED = "affected"

    #: Evidence was insufficient to determine either way. Routes to human
    #: review. The AI adjudicator MUST be able to return this — without an
    #: abstain path the "unsure" bucket stays silently empty and every
    #: ambiguous case gets forced into a confident-looking verdict.
    UNDER_INVESTIGATION = "in_triage"


class Justification(StrEnum):
    """Why a ``NOT_AFFECTED`` determination holds.

    These are the CycloneDX VEX justifications, and they map onto the evidence
    tiers deliberately: a justification is only permitted if the tier that
    produced it is allowed to justify a determination at all.
    """

    #: The vulnerable class is not in the shipped artifact. Tier 1 proof —
    #: catches shading, minimization, ``<filters>``, and tree-shaking.
    CODE_NOT_PRESENT = "code_not_present"

    #: The vulnerable code ships but nothing references it. Tier 2:
    #: constant-pool and source evidence, defeated by reflection.
    CODE_NOT_REACHABLE = "code_not_reachable"

    #: Exploitation needs a companion/gadget component absent from the
    #: classpath. Tier 2.
    REQUIRES_DEPENDENCY = "requires_dependency"

    #: Exploitation needs a configuration that is absent, *and* the library
    #: default is safe. Tier 2. The second half is not optional: "we didn't set
    #: it" is meaningless when the unsafe behaviour is the default.
    REQUIRES_CONFIGURATION = "requires_configuration"

    #: The runtime (JDK/Node/.NET version) falls outside the affected range.
    #: Tier 2.
    REQUIRES_ENVIRONMENT = "requires_environment"

    #: Network controls prevent reach. Tier 3 ONLY — declared so inbound VEX
    #: documents parse, but rejected as a basis for a determination.
    PROTECTED_AT_PERIMETER = "protected_at_perimeter"

    #: A compensating control blocks exploitation. Tier 3 ONLY, same
    #: restriction.
    PROTECTED_BY_MITIGATING_CONTROL = "protected_by_mitigating_control"

    def justifies_determination(self) -> bool:
        """Whether this justification may, on its own, support ``NOT_AFFECTED``.

        The perimeter and mitigating-control justifications are deliberately
        excluded. App context — exposure, criticality, network position — is not
        reliably available in this environment, and by policy it may only
        escalate severity or route to human review. It may never be the reason a
        vulnerability is declared not applicable. This is the one-directional
        Tier 3 rule, enforced in code rather than left to reviewer discipline.
        """
        return self in _JUSTIFYING


_JUSTIFYING = frozenset(
    {
        Justification.CODE_NOT_PRESENT,
        Justification.CODE_NOT_REACHABLE,
        Justification.REQUIRES_DEPENDENCY,
        Justification.REQUIRES_CONFIGURATION,
        Justification.REQUIRES_ENVIRONMENT,
    }
)


class EvidenceTier(IntEnum):
    """The strength of the evidence behind a signal."""

    #: Deterministic proof. May auto-determine ``NOT_AFFECTED`` on its own.
    PROOF = 1

    #: Strong but defeasible evidence — reflection and dynamic dispatch can
    #: overturn it. May auto-determine only with an independent second
    #: confirmation.
    STRONG = 2

    #: May ONLY raise severity or route to human review. Never contributes to a
    #: ``NOT_AFFECTED`` determination.
    ESCALATION = 3

    def may_justify(self) -> bool:
        """Whether evidence at this tier can support a ``NOT_AFFECTED`` outcome."""
        return self in (EvidenceTier.PROOF, EvidenceTier.STRONG)

    def requires_second_confirmation(self) -> bool:
        """Whether an auto-determination here needs an independent refuting pass."""
        return self is EvidenceTier.STRONG


class Confidence(StrEnum):
    """The adjudicator's self-reported certainty."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    #: The abstention signal. Any adjudicator returning this routes the finding
    #: to a human regardless of the state it proposed.
    INSUFFICIENT = "insufficient_evidence"

    def abstains(self) -> bool:
        return self in (Confidence.INSUFFICIENT, Confidence.LOW)


class DeterminationError(ValueError):
    """Raised when a determination violates the portal's safety invariants."""


@dataclass(frozen=True, slots=True)
class Determination:
    """The recorded conclusion for one vulnerability against one application, at
    one assessed commit."""

    state: State
    tier: EvidenceTier
    confidence: Confidence
    justification: Justification | None = None

    #: Point at rows in the evidence store. A determination with no evidence
    #: references is not auditable, and is rejected by :meth:`validate`.
    evidence_refs: tuple[str, ...] = ()

    #: What the adjudicator wanted and could not get. This is the input to
    #: improving the collectors — an empty "unsure" bucket alongside a full
    #: missing-evidence list means the collectors, not the model, are the
    #: bottleneck.
    missing_evidence: tuple[str, ...] = field(default=())

    def validate(self) -> None:
        """Enforce the invariants that keep determinations defensible.

        Raises:
            DeterminationError: if the determination could not be defended in an
                audit.
        """
        # Only NOT_AFFECTED suppresses anything, so only it carries these rules.
        if self.state is not State.NOT_AFFECTED:
            return

        if not self.tier.may_justify():
            raise DeterminationError(
                f"tier {self.tier.value} evidence may not justify a not_affected "
                "determination: escalation-only signals can raise severity or route to "
                "review, never clear a finding"
            )
        if self.justification is None:
            raise DeterminationError("not_affected determination requires a justification")
        if not self.justification.justifies_determination():
            raise DeterminationError(
                f"justification {self.justification.value!r} may not support a "
                "not_affected determination"
            )
        if self.confidence.abstains():
            raise DeterminationError(
                f"confidence {self.confidence.value!r} must route to human review, "
                "not a not_affected determination"
            )
        if not self.evidence_refs:
            raise DeterminationError(
                "not_affected determination requires at least one evidence reference"
            )

    @property
    def suppresses(self) -> bool:
        """Whether this determination results in an IQ waiver being created."""
        return self.state is State.NOT_AFFECTED
