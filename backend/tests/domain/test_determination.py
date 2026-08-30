"""Safety invariants for determinations.

These tests encode policy, not preference. If one of them starts failing, the
portal has become capable of clearing a finding it should not clear.
"""

from __future__ import annotations

import pytest

from app.domain.determination import (
    Confidence,
    Determination,
    DeterminationError,
    EvidenceTier,
    Justification,
    State,
)

ALL_JUSTIFICATIONS = list(Justification)
ALL_CONFIDENCES = list(Confidence)


class TestTier3NeverClears:
    """The load-bearing property of the whole portal.

    App context — exposure, criticality, network position — is not reliably
    available in this environment. By policy it may raise severity or route to a
    human, but it must never be the reason a vulnerability is declared not
    applicable.
    """

    @pytest.mark.parametrize("justification", ALL_JUSTIFICATIONS)
    @pytest.mark.parametrize("confidence", ALL_CONFIDENCES)
    def test_escalation_tier_is_always_rejected(
        self, justification: Justification, confidence: Confidence
    ) -> None:
        determination = Determination(
            state=State.NOT_AFFECTED,
            tier=EvidenceTier.ESCALATION,
            confidence=confidence,
            justification=justification,
            evidence_refs=("ev-1",),
        )
        with pytest.raises(DeterminationError):
            determination.validate()


class TestPerimeterJustifications:
    """Perimeter and mitigating-control justifications describe controls *around*
    a vulnerability, not the absence of one. They must be rejected even when the
    tier would otherwise permit a determination."""

    @pytest.mark.parametrize(
        "justification",
        [Justification.PROTECTED_AT_PERIMETER, Justification.PROTECTED_BY_MITIGATING_CONTROL],
    )
    @pytest.mark.parametrize("tier", list(EvidenceTier))
    def test_rejected_at_every_tier(
        self, justification: Justification, tier: EvidenceTier
    ) -> None:
        determination = Determination(
            state=State.NOT_AFFECTED,
            tier=tier,
            confidence=Confidence.HIGH,
            justification=justification,
            evidence_refs=("ev-1",),
        )
        with pytest.raises(DeterminationError):
            determination.validate()


class TestAbstention:
    """A model that says "not affected, but I lack evidence" is describing a
    human review, not a determination."""

    @pytest.mark.parametrize("confidence", [Confidence.INSUFFICIENT, Confidence.LOW])
    def test_abstention_cannot_clear(self, confidence: Confidence) -> None:
        determination = Determination(
            state=State.NOT_AFFECTED,
            tier=EvidenceTier.PROOF,
            confidence=confidence,
            justification=Justification.CODE_NOT_PRESENT,
            evidence_refs=("ev-1",),
        )
        with pytest.raises(DeterminationError):
            determination.validate()


class TestAuditability:
    def test_not_affected_requires_evidence(self) -> None:
        determination = Determination(
            state=State.NOT_AFFECTED,
            tier=EvidenceTier.PROOF,
            confidence=Confidence.HIGH,
            justification=Justification.CODE_NOT_PRESENT,
        )
        with pytest.raises(DeterminationError, match="evidence reference"):
            determination.validate()

    def test_not_affected_requires_justification(self) -> None:
        determination = Determination(
            state=State.NOT_AFFECTED,
            tier=EvidenceTier.PROOF,
            confidence=Confidence.HIGH,
            evidence_refs=("ev-1",),
        )
        with pytest.raises(DeterminationError, match="justification"):
            determination.validate()


class TestValidDeterminations:
    def test_tier1_code_not_present(self) -> None:
        Determination(
            state=State.NOT_AFFECTED,
            tier=EvidenceTier.PROOF,
            confidence=Confidence.HIGH,
            justification=Justification.CODE_NOT_PRESENT,
            evidence_refs=("ev-artifact-scan",),
        ).validate()

    def test_tier2_gadget_absent(self) -> None:
        Determination(
            state=State.NOT_AFFECTED,
            tier=EvidenceTier.STRONG,
            confidence=Confidence.HIGH,
            justification=Justification.REQUIRES_DEPENDENCY,
            evidence_refs=("ev-classpath", "ev-refute-pass"),
        ).validate()

    @pytest.mark.parametrize("state", [State.AFFECTED, State.UNDER_INVESTIGATION])
    def test_non_suppressing_states_need_no_justification(self, state: State) -> None:
        """Affected and under-investigation suppress nothing, so the
        justification rules do not apply to them."""
        Determination(
            state=state,
            tier=EvidenceTier.ESCALATION,
            confidence=Confidence.INSUFFICIENT,
        ).validate()

    def test_only_not_affected_suppresses(self) -> None:
        assert Determination(
            state=State.NOT_AFFECTED,
            tier=EvidenceTier.PROOF,
            confidence=Confidence.HIGH,
            justification=Justification.CODE_NOT_PRESENT,
            evidence_refs=("ev-1",),
        ).suppresses
        for state in (State.AFFECTED, State.UNDER_INVESTIGATION):
            assert not Determination(
                state=state, tier=EvidenceTier.PROOF, confidence=Confidence.HIGH
            ).suppresses


class TestTierRules:
    def test_proof_needs_no_second_confirmation(self) -> None:
        assert not EvidenceTier.PROOF.requires_second_confirmation()

    def test_strong_evidence_is_defeasible_and_needs_confirmation(self) -> None:
        assert EvidenceTier.STRONG.requires_second_confirmation()

    def test_escalation_may_never_justify(self) -> None:
        assert not EvidenceTier.ESCALATION.may_justify()
