"""Tests for Tier 3 rules (``app/rules/tier3.py``).

Tier 3 produces signals, never clearances. The load-bearing test in this file
is ``TestNeverClears::test_no_combination_of_tier3_signals_ever_yields_not_affected``
— a property test generated over the cartesian product of representative
values for every ``Tier3Signals`` field, per the Task 4 brief's explicit
instruction to generate combinations rather than enumerate a few.
"""

from __future__ import annotations

import itertools

from app.domain.determination import EvidenceTier
from app.evidence.pack import ComponentEvidence, EvidencePack
from app.provenance.fingerprint import FingerprintResult, Verdict
from app.repos.models import FindingOutcome
from app.rules.engine import RuleEngine, RuleVerdict, Tier3Signals
from app.rules.tier1 import ClassAbsent
from app.rules.tier3 import CvssVector, Epss, Kev, NoFixAvailable

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

COMPONENT = ComponentEvidence(
    cve="CVE-2024-0001",
    class_paths=["com/example/Vulnerable.class"],
    class_present=True,
    referenced=True,
    reference_scan_conclusive=True,
)

_NETWORK_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_LOCAL_VECTOR = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class TestKev:
    def test_metadata(self) -> None:
        rule = Kev()
        assert rule.id == "t3-kev"
        assert rule.tier is EvidenceTier.ESCALATION

    def test_satisfied_when_kev(self) -> None:
        rule = Kev()
        result = rule.evaluate(PACK, COMPONENT, Tier3Signals(kev=True))
        assert result.verdict is RuleVerdict.SATISFIED
        assert result.justification is None
        assert result.tier is EvidenceTier.ESCALATION

    def test_not_satisfied_when_not_kev(self) -> None:
        rule = Kev()
        result = rule.evaluate(PACK, COMPONENT, Tier3Signals(kev=False))
        assert result.verdict is RuleVerdict.NOT_SATISFIED

    def test_unanswerable_when_kev_not_looked_up(self) -> None:
        """Fix round 1: kev is now bool | None. None means 'unknown' —
        distinct from a confirmed 'not KEV' — so a KEV lookup that never ran,
        or that failed, must not read as 'this is not on KEV'."""
        rule = Kev()
        result = rule.evaluate(PACK, COMPONENT, Tier3Signals(kev=None))
        assert result.verdict is RuleVerdict.UNANSWERABLE
        assert result.justification is None

    def test_default_tier3_signals_still_has_kev_false_not_unknown(self) -> None:
        """The bare Tier3Signals() default was deliberately left at kev=False
        (unchanged) rather than moved to kev=None, so a caller that omits
        tier3_signals entirely still gets RuleEngine's documented
        blocker-free outcome — only a caller that positively knows the
        lookup resolved to 'unknown' should pass kev=None explicitly. See
        Tier3Signals' own docstring for the judgment call this encodes."""
        rule = Kev()
        result = rule.evaluate(PACK, COMPONENT, Tier3Signals())
        assert result.verdict is RuleVerdict.NOT_SATISFIED


class TestEpss:
    def test_metadata(self) -> None:
        rule = Epss()
        assert rule.id == "t3-epss"
        assert rule.tier is EvidenceTier.ESCALATION

    def test_satisfied_at_or_above_threshold(self) -> None:
        rule = Epss()
        result = rule.evaluate(PACK, COMPONENT, Tier3Signals(epss=0.5))
        assert result.verdict is RuleVerdict.SATISFIED
        assert result.justification is None

    def test_not_satisfied_below_threshold(self) -> None:
        rule = Epss()
        result = rule.evaluate(PACK, COMPONENT, Tier3Signals(epss=0.01))
        assert result.verdict is RuleVerdict.NOT_SATISFIED

    def test_unanswerable_when_not_looked_up(self) -> None:
        """None means 'not looked up', never coerced to 0 (Tier3Signals'
        own docstring) — a missing lookup must not read as 'low risk'."""
        rule = Epss()
        result = rule.evaluate(PACK, COMPONENT, Tier3Signals(epss=None))
        assert result.verdict is RuleVerdict.UNANSWERABLE
        assert result.justification is None


class TestCvssVector:
    def test_metadata(self) -> None:
        rule = CvssVector()
        assert rule.id == "t3-cvss-vector"
        assert rule.tier is EvidenceTier.ESCALATION

    def test_satisfied_for_high_severity_network_vector(self) -> None:
        rule = CvssVector()
        signals = Tier3Signals(cvss_base_score=8.1, cvss_vector=_NETWORK_VECTOR)
        result = rule.evaluate(PACK, COMPONENT, signals)
        assert result.verdict is RuleVerdict.SATISFIED
        assert result.justification is None

    def test_not_satisfied_for_local_vector(self) -> None:
        rule = CvssVector()
        signals = Tier3Signals(cvss_base_score=8.1, cvss_vector=_LOCAL_VECTOR)
        result = rule.evaluate(PACK, COMPONENT, signals)
        assert result.verdict is RuleVerdict.NOT_SATISFIED

    def test_not_satisfied_below_high_severity(self) -> None:
        rule = CvssVector()
        signals = Tier3Signals(cvss_base_score=4.0, cvss_vector=_NETWORK_VECTOR)
        result = rule.evaluate(PACK, COMPONENT, signals)
        assert result.verdict is RuleVerdict.NOT_SATISFIED

    def test_unanswerable_when_vector_not_looked_up(self) -> None:
        rule = CvssVector()
        signals = Tier3Signals(cvss_base_score=9.8, cvss_vector=None)
        result = rule.evaluate(PACK, COMPONENT, signals)
        assert result.verdict is RuleVerdict.UNANSWERABLE

    def test_unanswerable_when_score_not_looked_up(self) -> None:
        rule = CvssVector()
        signals = Tier3Signals(cvss_base_score=None, cvss_vector=_NETWORK_VECTOR)
        result = rule.evaluate(PACK, COMPONENT, signals)
        assert result.verdict is RuleVerdict.UNANSWERABLE


class TestNoFixAvailable:
    def test_metadata(self) -> None:
        rule = NoFixAvailable()
        assert rule.id == "t3-no-fix-available"
        assert rule.tier is EvidenceTier.ESCALATION

    def test_satisfied_when_no_fix_available(self) -> None:
        rule = NoFixAvailable()
        result = rule.evaluate(PACK, COMPONENT, Tier3Signals(fix_available=False))
        assert result.verdict is RuleVerdict.SATISFIED
        assert result.justification is None

    def test_not_satisfied_when_fix_available(self) -> None:
        rule = NoFixAvailable()
        result = rule.evaluate(PACK, COMPONENT, Tier3Signals(fix_available=True))
        assert result.verdict is RuleVerdict.NOT_SATISFIED

    def test_unanswerable_when_fix_available_not_looked_up(self) -> None:
        """Fix round 1: fix_available is now bool | None. None means
        'unknown', distinct from a confirmed 'a fix exists'."""
        rule = NoFixAvailable()
        result = rule.evaluate(PACK, COMPONENT, Tier3Signals(fix_available=None))
        assert result.verdict is RuleVerdict.UNANSWERABLE
        assert result.justification is None

    def test_default_tier3_signals_still_has_fix_available_true_not_unknown(self) -> None:
        """Mirrors t3-kev's equivalent test: the bare Tier3Signals() default
        was deliberately left at fix_available=True (unchanged)."""
        rule = NoFixAvailable()
        result = rule.evaluate(PACK, COMPONENT, Tier3Signals())
        assert result.verdict is RuleVerdict.NOT_SATISFIED

    def test_never_a_determination_structurally(self) -> None:
        """This rule never sets a justification even when SATISFIED, so it
        can never be selected as a clearing candidate by
        RuleEngine._best_clearing_result — the RISK_ACCEPTANCE_REQUIRED
        routing is the determination service's job, not this rule's or the
        engine's (see app/rules/engine.py's own docstring, priority order
        point 4)."""
        engine = RuleEngine([NoFixAvailable()])
        outcome = engine.evaluate_component(PACK, COMPONENT, Tier3Signals(fix_available=False))
        assert outcome.proposed is not FindingOutcome.NOT_AFFECTED


class TestUnknownKevBlocks:
    """Fix round 1's second requirement: unknown KEV must block an automatic
    clear exactly like confirmed KEV, so an outage or failure in the KEV
    feed cannot quietly re-enable auto-clearing for the CVEs most likely to
    be exploited."""

    def test_unknown_kev_blocks_a_tier1_clear(self) -> None:
        # t1-class-absent (PROOF tier) would clear this on its own with a
        # blocker-free Tier3Signals. With kev=None it must not.
        rule = ClassAbsent()
        engine = RuleEngine([rule])
        component = ComponentEvidence(
            cve="CVE-2024-0001",
            class_paths=["com/example/Vulnerable.class"],
            class_present=False,
            referenced=False,
            reference_scan_conclusive=True,
        )
        clear_outcome = engine.evaluate_component(PACK, component, Tier3Signals(kev=False))
        assert clear_outcome.proposed is FindingOutcome.NOT_AFFECTED  # sanity: it would clear

        blocked_outcome = engine.evaluate_component(PACK, component, Tier3Signals(kev=None))
        assert blocked_outcome.proposed is FindingOutcome.NEEDS_REVIEW
        assert "kev" in blocked_outcome.blocked_by

    def test_confirmed_not_kev_does_not_block(self) -> None:
        rule = ClassAbsent()
        engine = RuleEngine([rule])
        component = ComponentEvidence(
            cve="CVE-2024-0001",
            class_paths=["com/example/Vulnerable.class"],
            class_present=False,
            referenced=False,
            reference_scan_conclusive=True,
        )
        outcome = engine.evaluate_component(PACK, component, Tier3Signals(kev=False))
        assert outcome.proposed is FindingOutcome.NOT_AFFECTED
        assert "kev" not in outcome.blocked_by


class TestNeverClears:
    """The load-bearing property test: no combination of Tier 3 signals, in
    any quantity or arrangement, ever yields NOT_AFFECTED. Only the four
    Tier 3 rules are registered — no Tier 1/2 rule that could otherwise
    clear the finding — so any NOT_AFFECTED result here could only have come
    from Tier 3 evidence, which the policy this test enforces says can never
    happen.
    """

    def test_no_combination_of_tier3_signals_ever_yields_not_affected(self) -> None:
        # kev/fix_available now include None ("unknown") — fix round 1 —
        # since Tier3Signals.kev/fix_available became bool | None.
        kev_values = (True, False, None)
        epss_values = (None, 0.0, 0.01, 0.10, 0.5, 1.0)
        cvss_score_values = (None, 0.0, 4.0, 7.0, 9.0, 10.0)
        cvss_vector_values = (None, _NETWORK_VECTOR, _LOCAL_VECTOR)
        fix_available_values = (True, False, None)
        reachable_values = (True, False)

        engine = RuleEngine([Kev(), Epss(), CvssVector(), NoFixAvailable()])

        combinations = list(
            itertools.product(
                kev_values,
                epss_values,
                cvss_score_values,
                cvss_vector_values,
                fix_available_values,
                reachable_values,
            )
        )
        # Sanity check that this really is exercising the full cartesian
        # product and not, say, an accidentally-empty generator.
        assert len(combinations) == (
            len(kev_values)
            * len(epss_values)
            * len(cvss_score_values)
            * len(cvss_vector_values)
            * len(fix_available_values)
            * len(reachable_values)
        )

        for kev, epss, score, vector, fix_available, reachable in combinations:
            signals = Tier3Signals(
                kev=kev,
                epss=epss,
                cvss_base_score=score,
                cvss_vector=vector,
                reachable_with_call_path=reachable,
                fix_available=fix_available,
            )
            outcome = engine.evaluate_component(PACK, COMPONENT, signals)
            assert outcome.proposed is not FindingOutcome.NOT_AFFECTED, signals
