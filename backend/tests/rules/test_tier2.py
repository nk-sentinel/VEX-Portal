"""Tests for Tier 2 rules (``app/rules/tier2.py``).

Tier 2 is strong but defeasible: a clear here must always carry
``requires_second_confirmation``. The mandatory anti-check on
``t2-not-referenced`` is the single highest-value test in this file — see
``TestNotReferenced::test_anti_check_inconclusive_scan_never_satisfies``.
"""

from __future__ import annotations

from app.domain.determination import EvidenceTier, Justification
from app.evidence.pack import ComponentEvidence, EvidencePack
from app.provenance.fingerprint import FingerprintResult, Verdict
from app.repos.models import FindingOutcome
from app.rules.engine import RuleEngine, RuleVerdict, Tier3Signals
from app.rules.tier2 import GadgetAbsent, NotReferenced, RuntimeImmune

SIGNALS = Tier3Signals()

PACK = EvidencePack(
    provenance=FingerprintResult(
        verdict=Verdict.MATCH,
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
    class_present: bool = True,
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


class TestNotReferenced:
    def test_metadata(self) -> None:
        rule = NotReferenced()
        assert rule.id == "t2-not-referenced"
        assert rule.tier is EvidenceTier.STRONG

    def test_satisfied_when_unreferenced_and_scan_conclusive(self) -> None:
        rule = NotReferenced()
        component = _component(referenced=False, reference_scan_conclusive=True)
        result = rule.evaluate(PACK, component, SIGNALS)
        assert result.verdict is RuleVerdict.SATISFIED
        assert result.justification is Justification.CODE_NOT_REACHABLE

    def test_not_satisfied_when_referenced(self) -> None:
        rule = NotReferenced()
        component = _component(referenced=True, reference_scan_conclusive=True)
        result = rule.evaluate(PACK, component, SIGNALS)
        assert result.verdict is RuleVerdict.NOT_SATISFIED
        assert result.justification is None

    def test_anti_check_inconclusive_scan_never_satisfies(self) -> None:
        """The mandatory anti-check. An inconclusive scan (reflection,
        ServiceLoader, component scanning, JNDI, SpEL, an unreadable class,
        or an unexplained excluded-class gap) must return NOT_SATISFIED —
        never SATISFIED — even though 'referenced' is False. Reflection etc.
        reach classes no constant pool mentions; a rule that ignored this
        would clear findings on absent evidence.
        """
        rule = NotReferenced()
        component = _component(referenced=False, reference_scan_conclusive=False)
        result = rule.evaluate(PACK, component, SIGNALS)
        assert result.verdict is RuleVerdict.NOT_SATISFIED
        assert result.justification is None

    def test_unanswerable_when_no_implicated_classes_reported(self) -> None:
        rule = NotReferenced()
        component = _component(class_paths=(), referenced=False, reference_scan_conclusive=True)
        result = rule.evaluate(PACK, component, SIGNALS)
        assert result.verdict is RuleVerdict.UNANSWERABLE
        assert result.justification is None

    def test_tier2_clear_always_requires_second_confirmation(self) -> None:
        """Integration-level check through the real RuleEngine: a Tier 2
        clear must always carry requires_second_confirmation — it is
        defeasible evidence, not proof.

        This test is about the tier-safety property, not KEV/fix status, so
        it confirms those explicitly (kev=False, fix_available=True) rather
        than relying on a bare Tier3Signals(), which — since fix round 2 —
        means 'unknown' and would block on its own, confounding what this
        test is checking."""
        engine = RuleEngine([NotReferenced()])
        component = _component(referenced=False, reference_scan_conclusive=True)
        blocker_free_signals = Tier3Signals(kev=False, fix_available=True)
        outcome = engine.evaluate_component(PACK, component, blocker_free_signals)
        assert outcome.proposed is FindingOutcome.NOT_AFFECTED
        assert outcome.requires_second_confirmation is True

    def test_anti_check_through_the_engine_routes_to_review(self) -> None:
        """Same anti-check, exercised through the real engine: an
        inconclusive scan must not produce an auto-clear even when this is
        the only registered rule."""
        engine = RuleEngine([NotReferenced()])
        component = _component(referenced=False, reference_scan_conclusive=False)
        outcome = engine.evaluate_component(PACK, component, SIGNALS)
        assert outcome.proposed is FindingOutcome.NEEDS_REVIEW


class TestGadgetAbsent:
    """No evidence source exists for this rule today (see its docstring and
    the Task 2/3/4 report) — every case is UNANSWERABLE."""

    def test_metadata(self) -> None:
        rule = GadgetAbsent()
        assert rule.id == "t2-gadget-absent"
        assert rule.tier is EvidenceTier.STRONG

    def test_unanswerable_regardless_of_class_presence(self) -> None:
        rule = GadgetAbsent()
        for class_present in (True, False):
            result = rule.evaluate(PACK, _component(class_present=class_present), SIGNALS)
            assert result.verdict is RuleVerdict.UNANSWERABLE
            assert result.justification is None


class TestRuntimeImmune:
    """No evidence source exists for this rule today (see its docstring and
    the Task 2/3/4 report) — every case is UNANSWERABLE."""

    def test_metadata(self) -> None:
        rule = RuntimeImmune()
        assert rule.id == "t2-runtime-immune"
        assert rule.tier is EvidenceTier.STRONG

    def test_unanswerable_regardless_of_class_presence(self) -> None:
        rule = RuntimeImmune()
        for class_present in (True, False):
            result = rule.evaluate(PACK, _component(class_present=class_present), SIGNALS)
            assert result.verdict is RuleVerdict.UNANSWERABLE
            assert result.justification is None
