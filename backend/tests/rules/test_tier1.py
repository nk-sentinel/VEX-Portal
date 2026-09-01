"""Tests for Tier 1 rules (``app/rules/tier1.py``).

Tier 1 is proof: a rule here may clear a finding alone. The one property every
rule must satisfy is that a missing collector result never reads as "the class
is absent" — a rule that gets this backwards would let a broken collector
silently clear a live vulnerability. Each ``TestUnanswerable*`` class below
exists specifically to catch that regression.
"""

from __future__ import annotations

from app.domain.determination import EvidenceTier, Justification
from app.evidence.pack import ComponentEvidence, EvidencePack
from app.provenance.fingerprint import FingerprintResult, Verdict
from app.rules.engine import RuleVerdict, Tier3Signals
from app.rules.tier1 import ClassAbsent, ComponentAbsent, CveWithdrawn

SIGNALS = Tier3Signals()


def _pack(verdict: Verdict = Verdict.MATCH) -> EvidencePack:
    return EvidencePack(
        provenance=FingerprintResult(
            verdict=verdict,
            matched=5,
            report_total=5,
            unmatched_report_hashes=[],
            unmatched_artifact_hashes=[],
            surplus_ratio=0.0,
            ratio=1.0,
        )
    )


def _component(
    *,
    class_paths: tuple[str, ...] = ("com/example/Vulnerable.class",),
    class_present: bool = False,
    referenced: bool = False,
    reference_scan_conclusive: bool = True,
    cve: str = "CVE-2024-0001",
) -> ComponentEvidence:
    return ComponentEvidence(
        cve=cve,
        class_paths=list(class_paths),
        class_present=class_present,
        referenced=referenced,
        reference_scan_conclusive=reference_scan_conclusive,
    )


class TestClassAbsent:
    def test_metadata(self) -> None:
        rule = ClassAbsent()
        assert rule.id == "t1-class-absent"
        assert rule.tier is EvidenceTier.PROOF

    def test_satisfied_when_no_implicated_class_present(self) -> None:
        rule = ClassAbsent()
        result = rule.evaluate(_pack(), _component(class_present=False), SIGNALS)
        assert result.verdict is RuleVerdict.SATISFIED
        assert result.justification is Justification.CODE_NOT_PRESENT
        assert result.tier is EvidenceTier.PROOF

    def test_not_satisfied_when_class_present(self) -> None:
        rule = ClassAbsent()
        result = rule.evaluate(_pack(), _component(class_present=True), SIGNALS)
        assert result.verdict is RuleVerdict.NOT_SATISFIED
        assert result.justification is None

    def test_unanswerable_when_no_implicated_classes_reported(self) -> None:
        """A missing collector result (IQ reported no root-cause class paths
        for this CVE) must never read as 'the class is absent'."""
        rule = ClassAbsent()
        component = _component(class_paths=(), class_present=False)
        result = rule.evaluate(_pack(), component, SIGNALS)
        assert result.verdict is RuleVerdict.UNANSWERABLE
        assert result.justification is None


class TestComponentAbsent:
    """``t1-component-absent`` is implemented via an inference beyond the
    brief's literal text — see its docstring in ``app/rules/tier1.py`` and
    the Task 2/3/4 report. These tests lock in that interpretation.
    """

    def test_metadata(self) -> None:
        rule = ComponentAbsent()
        assert rule.id == "t1-component-absent"
        assert rule.tier is EvidenceTier.PROOF

    def test_satisfied_when_absent_and_provenance_confirmed(self) -> None:
        rule = ComponentAbsent()
        result = rule.evaluate(_pack(Verdict.MATCH), _component(class_present=False), SIGNALS)
        assert result.verdict is RuleVerdict.SATISFIED
        assert result.justification is Justification.CODE_NOT_PRESENT

    def test_not_satisfied_when_class_present(self) -> None:
        rule = ComponentAbsent()
        result = rule.evaluate(_pack(Verdict.MATCH), _component(class_present=True), SIGNALS)
        assert result.verdict is RuleVerdict.NOT_SATISFIED
        assert result.justification is None

    def test_not_satisfied_when_provenance_mismatch(self) -> None:
        """Absent class, but the artifact does not match the scanned report —
        the stronger 'not in the runtime artifact at all' claim is refused."""
        rule = ComponentAbsent()
        result = rule.evaluate(_pack(Verdict.MISMATCH), _component(class_present=False), SIGNALS)
        assert result.verdict is RuleVerdict.NOT_SATISFIED
        assert result.justification is None

    def test_unanswerable_when_no_implicated_classes_reported(self) -> None:
        rule = ComponentAbsent()
        component = _component(class_paths=(), class_present=False)
        result = rule.evaluate(_pack(Verdict.MATCH), component, SIGNALS)
        assert result.verdict is RuleVerdict.UNANSWERABLE

    def test_unanswerable_when_provenance_insufficient_data(self) -> None:
        """Too few report components to trust the artifact-report
        correspondence — the stronger whole-component claim cannot be made
        even though the narrower class-presence signal is populated."""
        rule = ComponentAbsent()
        component = _component(class_present=False)
        result = rule.evaluate(_pack(Verdict.INSUFFICIENT_DATA), component, SIGNALS)
        assert result.verdict is RuleVerdict.UNANSWERABLE
        assert result.justification is None


class TestCveWithdrawn:
    """No evidence source for CVE lifecycle status exists anywhere in this
    system today (see the rule's docstring and the Task 2/3/4 report) — every
    case is UNANSWERABLE. These tests confirm that is true regardless of the
    rest of the evidence pack, and that the rule can structurally never
    clear a finding even if that changes later.
    """

    def test_metadata(self) -> None:
        rule = CveWithdrawn()
        assert rule.id == "t1-cve-withdrawn"
        assert rule.tier is EvidenceTier.PROOF

    def test_unanswerable_regardless_of_class_presence(self) -> None:
        rule = CveWithdrawn()
        for class_present in (True, False):
            result = rule.evaluate(_pack(), _component(class_present=class_present), SIGNALS)
            assert result.verdict is RuleVerdict.UNANSWERABLE
            assert result.justification is None

    def test_unanswerable_regardless_of_provenance(self) -> None:
        rule = CveWithdrawn()
        for verdict in (Verdict.MATCH, Verdict.MISMATCH, Verdict.INSUFFICIENT_DATA):
            result = rule.evaluate(_pack(verdict), _component(), SIGNALS)
            assert result.verdict is RuleVerdict.UNANSWERABLE

    def test_never_carries_a_justification(self) -> None:
        """Structural guarantee: even if this rule's logic changes later, a
        justification-less result can never clear a finding
        (RuleEngine._best_clearing_result requires justification is not None).
        """
        rule = CveWithdrawn()
        result = rule.evaluate(_pack(), _component(), SIGNALS)
        assert result.justification is None
