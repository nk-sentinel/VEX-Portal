"""Tests for the rule engine core (``app/rules/engine.py``).

The engine is the ONLY place tier restrictions are enforced, so these tests
encode policy, not preference — mirroring ``tests/domain/test_determination.py``.
If one of these starts failing, the portal has become capable of clearing (or
failing to escalate) a finding it should not.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.domain.determination import EvidenceTier, Justification
from app.evidence.pack import ComponentEvidence, EvidencePack
from app.provenance.fingerprint import FingerprintResult, Verdict
from app.repos.models import FindingOutcome
from app.rules.engine import Rule, RuleEngine, RuleResult, RuleVerdict, Tier3Signals

PACK = EvidencePack(
    provenance=FingerprintResult(
        verdict=Verdict.MATCH,
        matched=1,
        report_total=1,
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

# A CVSS 3.1 vector satisfying AV:N/PR:N/UI:N with a base score of 9.8 — the
# hard-blocker shape from docs/design.md ("CVSS >= 9 with AV:N/PR:N/UI:N").
_NETWORK_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# Same base score, but exploitation requires local access — must NOT block.
_LOCAL_VECTOR = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@dataclass(frozen=True, slots=True)
class AlwaysSatisfied:
    """Test double: always SATISFIED at the given tier."""

    tier: EvidenceTier
    justification: Justification | None = None
    id: str = "test-always-satisfied"
    version: str = "1"

    def evaluate(
        self, pack: EvidencePack, component: ComponentEvidence, tier3_signals: Tier3Signals
    ) -> RuleResult:
        del pack, component, tier3_signals
        return RuleResult(
            rule_id=self.id,
            rule_version=self.version,
            tier=self.tier,
            verdict=RuleVerdict.SATISFIED,
            justification=self.justification,
        )


@dataclass(frozen=True, slots=True)
class AlwaysNotSatisfied:
    """Test double: always NOT_SATISFIED at the given tier."""

    tier: EvidenceTier
    id: str = "test-always-not-satisfied"
    version: str = "1"

    def evaluate(
        self, pack: EvidencePack, component: ComponentEvidence, tier3_signals: Tier3Signals
    ) -> RuleResult:
        del pack, component, tier3_signals
        return RuleResult(
            rule_id=self.id,
            rule_version=self.version,
            tier=self.tier,
            verdict=RuleVerdict.NOT_SATISFIED,
        )


@dataclass(frozen=True, slots=True)
class Inapplicable:
    """Test double: always INAPPLICABLE at the given tier."""

    tier: EvidenceTier
    id: str = "test-inapplicable"
    version: str = "1"

    def evaluate(
        self, pack: EvidencePack, component: ComponentEvidence, tier3_signals: Tier3Signals
    ) -> RuleResult:
        del pack, component, tier3_signals
        return RuleResult(
            rule_id=self.id,
            rule_version=self.version,
            tier=self.tier,
            verdict=RuleVerdict.INAPPLICABLE,
        )


@dataclass(frozen=True, slots=True)
class Unanswerable:
    """Test double: always UNANSWERABLE at the given tier."""

    tier: EvidenceTier
    id: str = "test-unanswerable"
    version: str = "1"

    def evaluate(
        self, pack: EvidencePack, component: ComponentEvidence, tier3_signals: Tier3Signals
    ) -> RuleResult:
        del pack, component, tier3_signals
        return RuleResult(
            rule_id=self.id,
            rule_version=self.version,
            tier=self.tier,
            verdict=RuleVerdict.UNANSWERABLE,
        )


def test_rule_test_doubles_satisfy_the_protocol() -> None:
    assert isinstance(AlwaysSatisfied(tier=EvidenceTier.PROOF), Rule)


class TestTierSafetyRule:
    """The load-bearing property of the whole engine: only Tier 1/2 evidence,
    with a permitted justification, may clear a finding."""

    def test_tier3_rule_alone_can_never_clear_a_finding(self) -> None:
        engine = RuleEngine([AlwaysSatisfied(tier=EvidenceTier.ESCALATION)])
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.proposed is not FindingOutcome.NOT_AFFECTED

    def test_a_tier1_rule_alone_can_clear_a_finding(self) -> None:
        engine = RuleEngine(
            [
                AlwaysSatisfied(
                    tier=EvidenceTier.PROOF, justification=Justification.CODE_NOT_PRESENT
                )
            ]
        )
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.proposed is FindingOutcome.NOT_AFFECTED
        assert outcome.tier is EvidenceTier.PROOF
        assert outcome.justification is Justification.CODE_NOT_PRESENT
        assert outcome.requires_second_confirmation is False

    def test_a_tier2_rule_alone_requires_a_second_confirmation(self) -> None:
        engine = RuleEngine(
            [
                AlwaysSatisfied(
                    tier=EvidenceTier.STRONG, justification=Justification.CODE_NOT_REACHABLE
                )
            ]
        )
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.proposed is FindingOutcome.NOT_AFFECTED
        assert outcome.requires_second_confirmation is True

    @pytest.mark.parametrize(
        "justification",
        [Justification.PROTECTED_AT_PERIMETER, Justification.PROTECTED_BY_MITIGATING_CONTROL],
    )
    @pytest.mark.parametrize("tier", [EvidenceTier.PROOF, EvidenceTier.STRONG])
    def test_a_rejected_justification_never_clears_even_at_a_clearing_tier(
        self, tier: EvidenceTier, justification: Justification
    ) -> None:
        # Tier alone is not enough — the justification itself must be one
        # Justification.justifies_determination() permits. Perimeter and
        # mitigating-control justifications describe app context, which is
        # the Tier 3 rule under a different name.
        engine = RuleEngine([AlwaysSatisfied(tier=tier, justification=justification)])
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.proposed is not FindingOutcome.NOT_AFFECTED

    def test_a_satisfied_rule_with_no_justification_never_clears(self) -> None:
        engine = RuleEngine([AlwaysSatisfied(tier=EvidenceTier.PROOF, justification=None)])
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.proposed is not FindingOutcome.NOT_AFFECTED

    def test_proof_wins_over_strong_when_both_clear(self) -> None:
        # The strongest (least defeasible) evidence should decide — a Tier 2
        # rule firing alongside a Tier 1 proof must not force an unnecessary
        # second confirmation onto a finding Tier 1 already proved.
        engine = RuleEngine(
            [
                AlwaysSatisfied(
                    tier=EvidenceTier.STRONG,
                    justification=Justification.CODE_NOT_REACHABLE,
                    id="t2-not-referenced",
                ),
                AlwaysSatisfied(
                    tier=EvidenceTier.PROOF,
                    justification=Justification.CODE_NOT_PRESENT,
                    id="t1-class-absent",
                ),
            ]
        )
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.tier is EvidenceTier.PROOF
        assert outcome.justification is Justification.CODE_NOT_PRESENT
        assert outcome.requires_second_confirmation is False


class TestUnanswerable:
    """UNANSWERABLE means a rule's evidence was missing, not that its
    condition failed. It must never read as NOT_SATISFIED."""

    def test_an_unanswerable_rule_makes_the_finding_inconclusive_never_clear(self) -> None:
        engine = RuleEngine(
            [
                AlwaysSatisfied(
                    tier=EvidenceTier.PROOF, justification=Justification.CODE_NOT_PRESENT
                ),
                Unanswerable(tier=EvidenceTier.PROOF),
            ]
        )
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.proposed is FindingOutcome.NEEDS_REVIEW

    def test_unanswerable_overrides_a_clear_even_at_a_lower_tier(self) -> None:
        # An UNANSWERABLE Tier 3 rule must still force review, even though
        # Tier 3 alone could never have blocked or cleared anything itself.
        engine = RuleEngine(
            [
                AlwaysSatisfied(
                    tier=EvidenceTier.PROOF, justification=Justification.CODE_NOT_PRESENT
                ),
                Unanswerable(tier=EvidenceTier.ESCALATION),
            ]
        )
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.proposed is FindingOutcome.NEEDS_REVIEW

    def test_unanswerable_alone_is_needs_review_not_affected(self) -> None:
        engine = RuleEngine([Unanswerable(tier=EvidenceTier.PROOF)])
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.proposed is FindingOutcome.NEEDS_REVIEW


class TestHardBlockers:
    """KEV, IQ's reachable-with-call-path signal, EPSS above threshold, and
    CVSS >= 9 with AV:N/PR:N/UI:N override any amount of Tier 1/2 proof."""

    _CLEARING = [
        AlwaysSatisfied(tier=EvidenceTier.PROOF, justification=Justification.CODE_NOT_PRESENT)
    ]

    def test_a_hard_blocker_overrides_every_clearing_rule(self) -> None:
        engine = RuleEngine(self._CLEARING)
        outcome = engine.evaluate_component(
            PACK, COMPONENT, tier3_signals=Tier3Signals(kev=True)
        )
        assert outcome.proposed is FindingOutcome.NEEDS_REVIEW
        assert "kev" in outcome.blocked_by

    def test_reachable_with_call_path_blocks(self) -> None:
        engine = RuleEngine(self._CLEARING)
        outcome = engine.evaluate_component(
            PACK, COMPONENT, tier3_signals=Tier3Signals(reachable_with_call_path=True)
        )
        assert outcome.proposed is FindingOutcome.NEEDS_REVIEW
        assert "reachable" in outcome.blocked_by

    def test_epss_at_or_above_threshold_blocks(self) -> None:
        engine = RuleEngine(self._CLEARING, epss_threshold=0.10)
        outcome = engine.evaluate_component(PACK, COMPONENT, tier3_signals=Tier3Signals(epss=0.10))
        assert outcome.proposed is FindingOutcome.NEEDS_REVIEW
        assert "epss" in outcome.blocked_by

    def test_epss_below_threshold_does_not_block(self) -> None:
        engine = RuleEngine(self._CLEARING, epss_threshold=0.10)
        outcome = engine.evaluate_component(PACK, COMPONENT, tier3_signals=Tier3Signals(epss=0.05))
        assert outcome.proposed is FindingOutcome.NOT_AFFECTED
        assert outcome.blocked_by == frozenset()

    def test_cvss_9_with_network_vector_blocks(self) -> None:
        engine = RuleEngine(self._CLEARING)
        outcome = engine.evaluate_component(
            PACK,
            COMPONENT,
            tier3_signals=Tier3Signals(cvss_base_score=9.8, cvss_vector=_NETWORK_VECTOR),
        )
        assert outcome.proposed is FindingOutcome.NEEDS_REVIEW
        assert "cvss" in outcome.blocked_by

    def test_cvss_9_with_local_vector_does_not_block(self) -> None:
        # High score alone is not enough — the hard blocker is specifically
        # AV:N/PR:N/UI:N (unauthenticated, no user interaction, over the
        # network). A local-only exploit at the same score is not it.
        engine = RuleEngine(self._CLEARING)
        outcome = engine.evaluate_component(
            PACK,
            COMPONENT,
            tier3_signals=Tier3Signals(cvss_base_score=9.8, cvss_vector=_LOCAL_VECTOR),
        )
        assert outcome.proposed is FindingOutcome.NOT_AFFECTED
        assert "cvss" not in outcome.blocked_by

    def test_cvss_below_9_does_not_block_even_with_network_vector(self) -> None:
        engine = RuleEngine(self._CLEARING)
        outcome = engine.evaluate_component(
            PACK,
            COMPONENT,
            tier3_signals=Tier3Signals(cvss_base_score=8.9, cvss_vector=_NETWORK_VECTOR),
        )
        assert outcome.proposed is FindingOutcome.NOT_AFFECTED

    def test_missing_cvss_vector_does_not_block_on_score_alone(self) -> None:
        engine = RuleEngine(self._CLEARING)
        outcome = engine.evaluate_component(
            PACK, COMPONENT, tier3_signals=Tier3Signals(cvss_base_score=9.9, cvss_vector=None)
        )
        assert outcome.proposed is FindingOutcome.NOT_AFFECTED

    def test_no_signals_at_all_blocks_nothing(self) -> None:
        engine = RuleEngine(self._CLEARING)
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.blocked_by == frozenset()
        assert outcome.proposed is FindingOutcome.NOT_AFFECTED

    def test_multiple_blockers_are_all_recorded(self) -> None:
        engine = RuleEngine(self._CLEARING)
        outcome = engine.evaluate_component(
            PACK,
            COMPONENT,
            tier3_signals=Tier3Signals(kev=True, reachable_with_call_path=True),
        )
        assert outcome.blocked_by == frozenset({"kev", "reachable"})


class TestRuleTrace:
    """Every rule that ran must be recorded, regardless of what it decided —
    the reviewer's trust surface and the audit record."""

    def test_every_rule_that_ran_is_recorded_even_when_it_did_not_decide(self) -> None:
        engine = RuleEngine(
            [
                AlwaysSatisfied(
                    tier=EvidenceTier.PROOF,
                    justification=Justification.CODE_NOT_PRESENT,
                    id="t1-class-absent",
                ),
                AlwaysSatisfied(tier=EvidenceTier.ESCALATION, id="t3-epss"),
            ]
        )
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert {r.rule_id for r in outcome.results} == {"t1-class-absent", "t3-epss"}

    def test_trace_includes_every_verdict_kind(self) -> None:
        engine = RuleEngine(
            [
                AlwaysSatisfied(
                    tier=EvidenceTier.PROOF, justification=Justification.CODE_NOT_PRESENT, id="a"
                ),
                AlwaysNotSatisfied(tier=EvidenceTier.PROOF, id="b"),
                Inapplicable(tier=EvidenceTier.STRONG, id="c"),
                Unanswerable(tier=EvidenceTier.ESCALATION, id="d"),
            ]
        )
        outcome = engine.evaluate_component(PACK, COMPONENT)
        verdicts_by_id = {r.rule_id: r.verdict for r in outcome.results}
        assert verdicts_by_id == {
            "a": RuleVerdict.SATISFIED,
            "b": RuleVerdict.NOT_SATISFIED,
            "c": RuleVerdict.INAPPLICABLE,
            "d": RuleVerdict.UNANSWERABLE,
        }
        assert len(outcome.results) == 4

    def test_no_rules_registered_yields_an_empty_trace(self) -> None:
        engine = RuleEngine([])
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.results == ()


class TestDefaultOutcome:
    """When nothing clears, nothing blocks, and nothing is unanswerable, the
    engine has no conclusive proposal of its own and defers rather than
    guessing AFFECTED."""

    def test_no_rules_registered_needs_review(self) -> None:
        engine = RuleEngine([])
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.proposed is FindingOutcome.NEEDS_REVIEW
        assert outcome.tier is None
        assert outcome.justification is None
        assert outcome.requires_second_confirmation is False

    def test_all_rules_not_satisfied_needs_review_not_affected(self) -> None:
        engine = RuleEngine(
            [
                AlwaysNotSatisfied(tier=EvidenceTier.PROOF),
                AlwaysNotSatisfied(tier=EvidenceTier.STRONG),
            ]
        )
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.proposed is FindingOutcome.NEEDS_REVIEW
        assert outcome.proposed is not FindingOutcome.AFFECTED

    def test_inapplicable_rules_alone_need_review(self) -> None:
        engine = RuleEngine([Inapplicable(tier=EvidenceTier.PROOF)])
        outcome = engine.evaluate_component(PACK, COMPONENT)
        assert outcome.proposed is FindingOutcome.NEEDS_REVIEW


class TestRuleResultShape:
    def test_detail_defaults_to_an_empty_dict(self) -> None:
        result = RuleResult(
            rule_id="x", rule_version="1", tier=EvidenceTier.PROOF, verdict=RuleVerdict.SATISFIED
        )
        assert result.detail == {}

    def test_detail_can_carry_free_form_evidence(self) -> None:
        result = RuleResult(
            rule_id="x",
            rule_version="1",
            tier=EvidenceTier.PROOF,
            verdict=RuleVerdict.SATISFIED,
            detail={"class_path": "com/example/Vulnerable.class"},
        )
        assert result.detail["class_path"] == "com/example/Vulnerable.class"
