"""Tier 1 rules: proof.

Each rule here may clear a finding on its own — SATISFIED at ``EvidenceTier.PROOF``
with a justification lets :meth:`~app.rules.engine.RuleEngine.evaluate_component`
propose ``NOT_AFFECTED`` without an independent second confirmation
(``EvidenceTier.requires_second_confirmation()`` is ``False`` for PROOF). That is
only safe because every condition below is deterministic: the vulnerable class
either shipped in the artifact or it did not, and :mod:`app.artifact.presence`
raises rather than silently reporting an unproven absence (see its module
docstring). See ``app/rules/engine.py``'s module docstring for the tier safety
rule every rule in this codebase relies on.

**The central hazard every rule below guards against.**
``ComponentEvidence.class_present`` is computed by ANDing the finding's
``class_paths`` (what IQ reported as implicated, ``rootCauses[].listOfPaths``)
against what the artifact actually contains. When ``class_paths`` is empty —
IQ never reported which class(es) this CVE implicates for this component — that
AND is vacuously ``False``. A rule that read ``class_present is False`` as
"the class is absent" without checking ``class_paths`` first would clear a
finding on a collector gap it never actually resolved: exactly the "a missing
collector result silently clears a live vulnerability" failure mode this
project's tests are built to catch. Every rule below checks ``class_paths``
first and returns ``UNANSWERABLE`` when it is empty, before ever consulting
``class_present``.

**Two rules in this module have no evidence source at all.**
``t1-component-absent`` (interpreted here as evidenced, but only via an
inference — see its docstring) and ``t1-cve-withdrawn`` (genuinely
unanswerable in every case — see its docstring) are both flagged in detail in
the Task 2/3/4 implementation report. Read that report's concerns section
before wiring either into a production rule registry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.domain.determination import EvidenceTier, Justification
from app.evidence.pack import ComponentEvidence, EvidencePack
from app.provenance.fingerprint import Verdict
from app.rules.engine import RuleEvaluation, RuleVerdict, Tier3Signals


def _make(
    rule_id: str,
    rule_version: str,
    tier: EvidenceTier,
    verdict: RuleVerdict,
    *,
    justification: Justification | None = None,
    detail: dict[str, object] | None = None,
) -> RuleEvaluation:
    """Build one :class:`RuleEvaluation`, defaulting ``detail`` to ``{}``.

    A tiny shared constructor so each rule's ``evaluate`` body reads as the
    condition it checks, not repeated ``RuleEvaluation(rule_id=..., ...)``
    boilerplate.
    """
    return RuleEvaluation(
        rule_id=rule_id,
        rule_version=rule_version,
        tier=tier,
        verdict=verdict,
        justification=justification,
        detail=detail if detail is not None else {},
    )


@dataclass(frozen=True, slots=True)
class ClassAbsent:
    """``t1-class-absent``: none of the CVE's implicated classes ship in the artifact.

    docs/design.md Tier 1 item 1: catches shading, minimization, ``<filters>``,
    and tree-shaking — the class was never in the report's dependency tree to
    begin with, or it was, but build-time processing dropped it.
    """

    id: str = field(default="t1-class-absent", init=False)
    version: str = field(default="1", init=False)
    tier: EvidenceTier = field(default=EvidenceTier.PROOF, init=False)

    def evaluate(
        self,
        pack: EvidencePack,
        component: ComponentEvidence,
        tier3_signals: Tier3Signals,
    ) -> RuleEvaluation:
        del pack, tier3_signals
        if not component.class_paths:
            # IQ reported no implicated class for this CVE/component pair.
            # class_present would be vacuously False here — a collector gap,
            # not proof of absence. See module docstring.
            return _make(
                self.id,
                self.version,
                self.tier,
                RuleVerdict.UNANSWERABLE,
                detail={
                    "cve": component.cve,
                    "reason": "no implicated class_paths reported for this CVE",
                },
            )
        if component.class_present:
            return _make(
                self.id,
                self.version,
                self.tier,
                RuleVerdict.NOT_SATISFIED,
                detail={"cve": component.cve, "class_paths": list(component.class_paths)},
            )
        return _make(
            self.id,
            self.version,
            self.tier,
            RuleVerdict.SATISFIED,
            justification=Justification.CODE_NOT_PRESENT,
            detail={"cve": component.cve, "class_paths": list(component.class_paths)},
        )


@dataclass(frozen=True, slots=True)
class ComponentAbsent:
    """``t1-component-absent``: the whole component is not in the runtime
    artifact at all — not just the implicated class, the entire dependency.

    docs/design.md Tier 1 item 2: "Component absent from the runtime artifact
    entirely (inspect artifact, not manifest)" — a coarser, stronger claim
    than ``t1-class-absent``'s "the implicated class specifically is absent":
    the whole dependency never shipped (e.g. it is scoped ``test``/
    ``devDependencies`` and never packaged), not merely shaded/filtered out
    of an otherwise-bundled library.

    **Interpretive gap, flagged in the Task 2/3/4 report.**
    ``ComponentEvidence`` carries no independent component identity (no
    sha1/purl) distinct from ``class_present``, so this rule cannot literally
    check "is library X present" the way its name and docs/design.md's
    phrasing imply — no such field exists anywhere reachable from
    ``Rule.evaluate``. What it CAN do, using only fields the pack already
    carries, is require a higher evidentiary bar before granting the
    stronger claim: the class-presence check must hold, AND the artifact
    must be a confirmed (``Verdict.MATCH``) rendering of the report's own
    component set. An artifact whose overall provenance is unproven
    (``Verdict.INSUFFICIENT_DATA``) should not be trusted to prove "not
    present AT ALL", even where it would be trusted for the narrower
    per-class claim ``t1-class-absent`` makes. This is an inference, not a
    literal reading of the brief — under this evidence model the two rules
    are otherwise evidentially identical.
    """

    id: str = field(default="t1-component-absent", init=False)
    version: str = field(default="1", init=False)
    tier: EvidenceTier = field(default=EvidenceTier.PROOF, init=False)

    def evaluate(
        self,
        pack: EvidencePack,
        component: ComponentEvidence,
        tier3_signals: Tier3Signals,
    ) -> RuleEvaluation:
        del tier3_signals
        if not component.class_paths:
            return _make(
                self.id,
                self.version,
                self.tier,
                RuleVerdict.UNANSWERABLE,
                detail={
                    "cve": component.cve,
                    "reason": "no implicated class_paths reported for this CVE",
                },
            )
        if pack.provenance.verdict is Verdict.INSUFFICIENT_DATA:
            return _make(
                self.id,
                self.version,
                self.tier,
                RuleVerdict.UNANSWERABLE,
                detail={
                    "cve": component.cve,
                    "reason": (
                        "provenance verdict is insufficient_data: cannot confirm the "
                        "artifact fully represents the scanned build, so whole-component "
                        "absence cannot be asserted with confidence"
                    ),
                },
            )
        if component.class_present:
            return _make(
                self.id,
                self.version,
                self.tier,
                RuleVerdict.NOT_SATISFIED,
                detail={"cve": component.cve, "class_paths": list(component.class_paths)},
            )
        if pack.provenance.verdict is Verdict.MISMATCH:
            return _make(
                self.id,
                self.version,
                self.tier,
                RuleVerdict.NOT_SATISFIED,
                detail={
                    "cve": component.cve,
                    "reason": (
                        "provenance verdict is mismatch: cannot assert whole-component "
                        "absence against an artifact that is a different build than the "
                        "one the report describes"
                    ),
                },
            )
        return _make(
            self.id,
            self.version,
            self.tier,
            RuleVerdict.SATISFIED,
            justification=Justification.CODE_NOT_PRESENT,
            detail={
                "cve": component.cve,
                "class_paths": list(component.class_paths),
                "provenance_verdict": pack.provenance.verdict.value,
            },
        )


@dataclass(frozen=True, slots=True)
class CveWithdrawn:
    """``t1-cve-withdrawn``: the CVE itself is withdrawn, disputed, or superseded.

    **Not a determination.** A withdrawn/disputed/superseded CVE is a DATA
    CORRECTION — the right fix is IQ's Security Vulnerability Override API,
    not a Not Affected determination. This rule therefore never sets a
    justification, even in a hypothetical SATISFIED branch:
    ``RuleEngine._best_clearing_result`` only treats a result as a clearing
    candidate when ``justification is not None`` (see ``app/rules/engine.py``),
    so a justification-less SATISFIED result can never clear a finding,
    structurally, regardless of tier. Any downstream service that wants to
    route a satisfied instance of this rule to a correction workflow (the way
    ``app/rules/tier3.py``'s ``t3-no-fix-available`` is routed to
    ``RISK_ACCEPTANCE_REQUIRED`` one layer above the engine) must inspect
    ``EngineOutcome.results`` for it directly.

    **No evidence source exists for this rule today — flagged prominently in
    the Task 2/3/4 report.** Nothing reachable from ``Rule.evaluate``'s
    parameters — not ``EvidencePack``, not ``ComponentEvidence``, not
    ``Tier3Signals`` — carries a CVE's lifecycle status
    (withdrawn/disputed/superseded/active). Nor does ``VulnDetail``
    (``app/adapters/protocols.py``), which is where such a field would need
    to originate before it could ever reach this rule. Every evaluation
    therefore returns ``UNANSWERABLE``: the evidence this rule needs is
    missing from the pack, in the strong sense that no pack this system
    currently builds can ever carry it — not a case this rule's own logic
    could get right or wrong.
    """

    id: str = field(default="t1-cve-withdrawn", init=False)
    version: str = field(default="1", init=False)
    tier: EvidenceTier = field(default=EvidenceTier.PROOF, init=False)

    def evaluate(
        self,
        pack: EvidencePack,
        component: ComponentEvidence,
        tier3_signals: Tier3Signals,
    ) -> RuleEvaluation:
        del pack, tier3_signals
        return _make(
            self.id,
            self.version,
            self.tier,
            RuleVerdict.UNANSWERABLE,
            detail={
                "cve": component.cve,
                "reason": (
                    "no evidence source for CVE lifecycle status (withdrawn/disputed/"
                    "superseded) exists in EvidencePack, ComponentEvidence, or "
                    "Tier3Signals; this rule cannot currently be answered"
                ),
            },
        )
