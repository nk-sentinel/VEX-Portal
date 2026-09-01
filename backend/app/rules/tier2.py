"""Tier 2 rules: strong but defeasible evidence.

Nothing here may clear a finding without an independent second confirmation.
``EvidenceTier.STRONG`` is deliberately defeasible: reflection, ``ServiceLoader``,
Spring component scanning, JNDI and SpEL can all reach classes that never appear
in a constant pool, so "compiled-reality evidence of non-use" is strong, not
proof. Every rule below reports at ``EvidenceTier.STRONG``, and
``RuleEngine.evaluate_component`` sets ``requires_second_confirmation=True``
whenever a STRONG-tier result decides the outcome — that part is enforced by the
engine itself (``EvidenceTier.requires_second_confirmation()``), not repeated
here.

**The anti-check is mandatory and lives on ``t2-not-referenced``.** A reference
scan that could not be trusted (an escape hatch was found, a class failed to
parse, nothing was scanned, or inventory excluded some class it could not
explain — see ``app/artifact/references.py``'s ``ReferenceScan.is_conclusive``)
must never be read as "therefore not referenced". See that rule's docstring for
why this is ``NOT_SATISFIED`` rather than ``UNANSWERABLE``.

**Two rules in this module have no evidence source at all.** ``t2-gadget-absent``
and ``t2-runtime-immune`` are both flagged in detail in the Task 2/3/4
implementation report — neither ``EvidencePack``, ``ComponentEvidence``, nor
``Tier3Signals`` carries a companion/gadget component's identity or presence, or
a runtime version claim. Read that report's concerns section before wiring
either into a production rule registry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.domain.determination import EvidenceTier, Justification
from app.evidence.pack import ComponentEvidence, EvidencePack
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

    Mirrors ``app/rules/tier1.py``'s helper of the same name and shape — kept
    as a small per-module duplicate rather than a shared import because
    neither brief calls for a new shared module, and the function is eight
    lines of pure construction.
    """
    return RuleEvaluation(
        rule_id=rule_id,
        rule_version=rule_version,
        tier=tier,
        verdict=verdict,
        justification=justification,
        detail=detail if detail is not None else {},
    )


@dataclass(slots=True)
class NotReferenced:
    """``t2-not-referenced``: nothing in the app's own bytecode references any
    implicated class, and the constant-pool scan was conclusive.

    **The mandatory anti-check.** ``reference_scan_conclusive`` is False when
    the scan found a dynamic-dispatch escape hatch (reflection,
    ``ServiceLoader``, Spring component scanning, JNDI, SpEL — see
    ``app/artifact/references.py``'s ``_ESCAPE_HATCH_MARKERS``), an unreadable
    class, zero classes scanned, or an excluded-class gap it cannot explain.
    Every one of those means "the application could reach code that never
    appears in a constant pool" — an inconclusive scan must never be read as
    evidence of non-reference, so this rule returns ``NOT_SATISFIED``, never
    ``SATISFIED``, whenever ``reference_scan_conclusive`` is False.

    That is ``NOT_SATISFIED``, not ``UNANSWERABLE`` — deliberately, and
    distinct from this rule's own ``UNANSWERABLE`` branch below. This rule's
    condition is a conjunction ("not referenced AND the scan was
    conclusive"); when the conclusive half is False the conjunction is False,
    full stop — that is exactly what ``RuleVerdict.NOT_SATISFIED`` means
    ("the rule evaluated and its condition does not hold"). Unlike
    ``class_paths`` being empty (a genuine collector gap — nothing was ever
    computed), ``reference_scan_conclusive`` is itself a complete, positive,
    always-populated fact the collector produces on every run (see
    ``ReferenceScan.is_conclusive``): the rule's own evidence is fully
    present, it just answers "no". Reporting UNANSWERABLE here instead would
    mean that virtually any real Spring Boot application — where
    ``@ComponentScan``/``Object.getClass()`` usage is ubiquitous, so
    ``is_conclusive()`` is False on most real bytecode (see this branch's
    CLAUDE.md, "Decide before merge" #3) — would have EVERY finding forced to
    ``NEEDS_REVIEW`` the moment this rule is registered, including ones a
    Tier 1 rule already proved conclusively, because an UNANSWERABLE result
    from any rule poisons the whole finding
    (``RuleEngine.evaluate_component``, priority order point 2). That would
    make Tier 1's "may clear a finding alone" property meaningless on most
    real artifacts.
    """

    id: str = field(default="t2-not-referenced", init=False)
    version: str = field(default="1", init=False)
    tier: EvidenceTier = field(default=EvidenceTier.STRONG, init=False)

    def evaluate(
        self,
        pack: EvidencePack,
        component: ComponentEvidence,
        tier3_signals: Tier3Signals,
    ) -> RuleEvaluation:
        del pack, tier3_signals
        if not component.class_paths:
            # Same collector-gap reasoning as t1-class-absent: with no
            # implicated class known, `referenced` would be vacuously False.
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
        if not component.reference_scan_conclusive:
            return _make(
                self.id,
                self.version,
                self.tier,
                RuleVerdict.NOT_SATISFIED,
                detail={
                    "cve": component.cve,
                    "reason": (
                        "reference scan was not conclusive; the anti-check refuses to "
                        "treat an untrustworthy non-reference as evidence"
                    ),
                },
            )
        if component.referenced:
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
            justification=Justification.CODE_NOT_REACHABLE,
            detail={"cve": component.cve, "class_paths": list(component.class_paths)},
        )


@dataclass(slots=True)
class GadgetAbsent:
    """``t2-gadget-absent``: SATISFIED when a required companion/gadget
    component is absent from the classpath (docs/design.md Tier 2 item 8).

    **No evidence source exists for this rule today — flagged prominently in
    the Task 2/3/4 report.** ``ComponentEvidence`` carries no per-library
    identity distinct from the CVE's own implicated ``class_paths`` (no
    purl/sha1, no per-dependency presence map), so there is no field this
    rule can read to determine whether a SPECIFIC companion library required
    for a gadget chain is present. ``class_present`` cannot substitute: it is
    a single boolean ORed across every path in ``class_paths`` and cannot
    distinguish "the vulnerable class is present but the gadget class is
    not" from any other combination — the per-path breakdown it would need
    is discarded before it ever reaches ``ComponentEvidence``. Every
    evaluation therefore returns ``UNANSWERABLE``. This needs a data-model
    addition (a gadget-component identity + presence signal) before it can
    do anything beyond that.
    """

    id: str = field(default="t2-gadget-absent", init=False)
    version: str = field(default="1", init=False)
    tier: EvidenceTier = field(default=EvidenceTier.STRONG, init=False)

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
                    "no companion/gadget component identity or presence signal exists in "
                    "EvidencePack, ComponentEvidence, or Tier3Signals; this rule cannot "
                    "currently be answered"
                ),
            },
        )


@dataclass(slots=True)
class RuntimeImmune:
    """``t2-runtime-immune``: SATISFIED when the runtime version falls
    outside the CVE's affected range (docs/design.md Tier 2 item 10).

    **No evidence source exists for this rule today — flagged prominently in
    the Task 2/3/4 report.** Neither ``EvidencePack``/``ComponentEvidence``
    (built purely from the artifact's own bytes) nor ``Tier3Signals``
    (KEV/EPSS/CVSS/reachability/fix availability) carries a runtime
    (JDK/Node/.NET) version claim or a CVE's affected-version range.
    ``VulnDetail.affected_version_range`` (``app/adapters/protocols.py``) is
    the closest existing field, but it is not threaded into
    ``Rule.evaluate``'s signature at all, and there is no runtime-version
    fact anywhere in this system to resolve it against even if it were.
    Every evaluation therefore returns ``UNANSWERABLE``.
    """

    id: str = field(default="t2-runtime-immune", init=False)
    version: str = field(default="1", init=False)
    tier: EvidenceTier = field(default=EvidenceTier.STRONG, init=False)

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
                    "no runtime-version or affected-version-range signal exists in "
                    "EvidencePack, ComponentEvidence, or Tier3Signals; this rule cannot "
                    "currently be answered"
                ),
            },
        )
