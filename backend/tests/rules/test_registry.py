"""Tests for the default rule registry (``app/rules/registry.py``).

The second test in this file — every ``ACTIVE_RULES`` entry can answer
something other than UNANSWERABLE — is the real guard the coordinator asked
for: it is what would have caught ``t1-cve-withdrawn``/``t2-gadget-absent``/
``t2-runtime-immune`` being included in the default registry in the first
place, before their always-UNANSWERABLE behaviour ever reached a real
finding and poisoned it to NEEDS_REVIEW.
"""

from __future__ import annotations

from app.evidence.pack import ComponentEvidence, EvidencePack
from app.provenance.fingerprint import FingerprintResult, Verdict
from app.rules.engine import RuleVerdict, Tier3Signals
from app.rules.registry import ACTIVE_RULES, PENDING_EVIDENCE
from app.rules.tier1 import CveWithdrawn
from app.rules.tier2 import GadgetAbsent, RuntimeImmune

# A single "fully answerable" evidence triple: every field every ACTIVE_RULES
# member reads is populated with a non-None, non-empty value, so none of them
# has any excuse to say UNANSWERABLE. This is deliberately generic, not
# per-rule — the point of the guard is that ANY well-formed input suffices,
# not a bespoke input engineered to flatter each rule individually.
_ANSWERABLE_PACK = EvidencePack(
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

_ANSWERABLE_COMPONENT = ComponentEvidence(
    cve="CVE-2024-0001",
    class_paths=["com/example/Vulnerable.class"],
    class_present=False,
    referenced=False,
    reference_scan_conclusive=True,
)

_ANSWERABLE_SIGNALS = Tier3Signals(
    kev=False,
    epss=0.5,
    cvss_base_score=9.8,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    reachable_with_call_path=False,
    fix_available=True,
)


class TestPendingEvidenceExcludedFromActive:
    def test_no_pending_rule_id_appears_in_active_rules(self) -> None:
        active_ids = {rule.id for rule in ACTIVE_RULES}
        for pending_id in PENDING_EVIDENCE:
            assert pending_id not in active_ids, (
                f"{pending_id!r} is in PENDING_EVIDENCE (no working evidence path) "
                "but was also found in ACTIVE_RULES — registering it would force "
                "every finding to NEEDS_REVIEW"
            )

    def test_pending_evidence_is_not_empty(self) -> None:
        """A trivially-true assertion above (vacuous over an empty dict) would
        not actually guard anything — pin the expected three entries."""
        assert set(PENDING_EVIDENCE) == {
            "t1-cve-withdrawn",
            "t2-gadget-absent",
            "t2-runtime-immune",
        }


class TestEveryActiveRuleCanAnswer:
    """The real guard: every ACTIVE_RULES member must be able to return
    something other than UNANSWERABLE for at least one constructible pack.
    A rule that can never do so does not belong in the default registry —
    see app/rules/registry.py's module docstring.
    """

    def test_every_active_rule_can_return_a_non_unanswerable_verdict(self) -> None:
        for rule in ACTIVE_RULES:
            result = rule.evaluate(_ANSWERABLE_PACK, _ANSWERABLE_COMPONENT, _ANSWERABLE_SIGNALS)
            assert result.verdict is not RuleVerdict.UNANSWERABLE, (
                f"{rule.id!r} returned UNANSWERABLE even against a fully-populated "
                "evidence pack — it has no working evidence path and belongs in "
                "PENDING_EVIDENCE, not ACTIVE_RULES"
            )

    def test_the_guard_actually_discriminates(self) -> None:
        """Confirms the guard above is not vacuously true: the three PENDING
        rules — deliberately excluded from ACTIVE_RULES — DO return
        UNANSWERABLE against this exact same fully-populated input, which is
        precisely why they are excluded."""
        pending_rules = (CveWithdrawn(), GadgetAbsent(), RuntimeImmune())
        for rule in pending_rules:
            result = rule.evaluate(_ANSWERABLE_PACK, _ANSWERABLE_COMPONENT, _ANSWERABLE_SIGNALS)
            assert result.verdict is RuleVerdict.UNANSWERABLE
