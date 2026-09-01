"""The rule engine: turns per-rule verdicts into one proposed outcome.

This module is deliberately narrow. It does not know what a class is, what a
CVE is, or how to parse bytecode — it only aggregates whatever the registered
:class:`Rule` implementations report, under one safety rule that no
individual rule may override: **only Tier 1 (PROOF) or Tier 2 (STRONG)
evidence, SATISFIED with a justification that
:meth:`~app.domain.determination.Justification.justifies_determination`
permits, may propose clearing a finding.** Tier 3 (ESCALATION) evidence, and
the hard blockers below, can only ever push a finding toward
``NEEDS_REVIEW`` — never away from it. This is the same one-directional rule
``app/domain/determination.py`` enforces on ``Determination.validate`` and
CLAUDE.md rule 2 states directly; it is enforced again here, independently,
so there is no path around it through the rule engine.

Priority order, evaluated every time :meth:`RuleEngine.evaluate_component`
runs:

1. **A hard blocker wins over everything.** KEV, IQ's own
   reachable-with-call-path signal, EPSS at or above threshold, or CVSS >= 9
   with ``AV:N/PR:N/UI:N`` (docs/design.md, "Deterministic decision tiers").
   No quantity of Tier 1/2 proof overrides it. Which blocker(s) fired is
   recorded in :attr:`EngineOutcome.blocked_by` so a reviewer does not have
   to reverse-engineer the reason. This check reads :class:`Tier3Signals`
   directly — it does not depend on any particular Tier 3 rule being
   registered, because a hard blocker is a safety invariant of the engine,
   not a registration accident.
2. **An UNANSWERABLE rule result forces review.** UNANSWERABLE means the
   evidence that rule needed was missing from the pack — not that the
   rule's condition failed. Treating it as NOT_SATISFIED would let a broken
   collector silently clear a finding. Any UNANSWERABLE result routes the
   *whole* finding to ``NEEDS_REVIEW``, even if a different rule separately
   cleared it — an unrelated unknown does not make a clear more trustworthy.
3. **Otherwise, the strongest qualifying clear wins.** If any registered
   rule is SATISFIED at a tier ``EvidenceTier.may_justify()`` allows, with a
   justification ``justifies_determination()`` permits, the finding
   proposes ``NOT_AFFECTED``. When more than one such rule fired, the
   lowest tier (PROOF over STRONG) decides, so a Tier 2 rule firing
   alongside a Tier 1 proof never forces an unnecessary second-confirmation
   requirement onto a finding Tier 1 already proved. A STRONG-tier decision
   always sets ``requires_second_confirmation`` — it is defeasible evidence
   (reflection, dynamic dispatch), not proof.
4. **Otherwise, the engine has nothing conclusive and proposes
   NEEDS_REVIEW.** The rule engine never proposes ``AFFECTED`` or
   ``RISK_ACCEPTANCE_REQUIRED`` on its own. ``AFFECTED`` is a closed-output
   value the AI adjudicator or a human reviewer asserts from positive
   evidence this engine does not collect (see docs/design/ui-spec.md's
   manual "( ) Not Affected / ( ) Affected" review action) — defaulting to
   it here would mean "no proof either way" quietly became "guilty".
   ``RISK_ACCEPTANCE_REQUIRED`` is assigned by the determination service
   (Phase 4, Task 8) when it sees a Tier 3 ``t3-no-fix-available`` result in
   the trace; that is a routing decision made by combining the trace with
   other context, not part of this aggregation step. Note that rule still
   only ever reports SATISFIED at tier ESCALATION, so point 1's "Tier 3
   never influences `proposed` except toward NEEDS_REVIEW" still holds
   *inside this module* — the RISK_ACCEPTANCE_REQUIRED routing happens one
   layer up, after this engine has already refused to call it NOT_AFFECTED.

Every rule that runs is recorded in :attr:`EngineOutcome.results`, in
registration order, regardless of its verdict or whether it decided
anything — the rule trace is the reviewer's trust surface and the audit
record. A determination whose reasoning cannot be reconstructed from it is
not defensible.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from app.domain.determination import EvidenceTier, Justification
from app.evidence.pack import ComponentEvidence, EvidencePack
from app.repos.models import FindingOutcome

#: CVSS base score floor for the CVSS hard blocker (docs/design.md: "CVSS >=
#: 9 with AV:N/PR:N/UI:N"). Unlike the EPSS threshold, this is not exposed
#: as a constructor parameter: both the brief and docs/design.md state it as
#: a fixed number, not a per-team admin setting the way the EPSS routing
#: threshold is (docs/design/ui-mockups.html has an "EPSS routing
#: threshold" admin field; there is no CVSS-floor equivalent).
_CVSS_BLOCK_SCORE = 9.0


class RuleVerdict(StrEnum):
    """What one rule concluded about one component — distinct from what the
    engine proposes overall for the finding."""

    #: The rule's condition holds.
    SATISFIED = "satisfied"

    #: The rule evaluated and its condition does not hold. This is evidence
    #: *of* something (e.g. the class is present), never mere absence of
    #: evidence — see UNANSWERABLE for that case.
    NOT_SATISFIED = "not_satisfied"

    #: The rule does not apply to this component at all (e.g. a
    #: runtime-immunity rule when no runtime claim is relevant to this
    #: finding). Distinct from UNANSWERABLE: the rule could evaluate, and
    #: its answer is "not relevant here", not "condition false" or "don't
    #: know".
    INAPPLICABLE = "inapplicable"

    #: The evidence this rule needed is missing from the pack. Not evidence
    #: of anything. Never treat this as NOT_SATISFIED: a collector that
    #: failed to run is not the same fact as "the condition does not hold".
    UNANSWERABLE = "unanswerable"


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    """One rule's verdict against one component.

    The engine evaluates rules, producing ``RuleEvaluation`` objects; those
    are persisted as :class:`~app.repos.models.RuleResult` rows. The two
    names are deliberately different even though the shapes rhyme
    (``rule_id``/``rule_version``/``tier``/verdict on both): this class is
    an in-flight evaluation result exchanged between :class:`Rule` and
    :class:`RuleEngine`, never itself written to the database, while
    ``app.repos.models.RuleResult`` is the persisted row a later task
    (Phase 4, Task 8) writes from it. Sharing one name across those two
    layers is exactly the kind of ambiguity that has already cost this
    project real holes — see the Task 1 report — so the names stay
    distinct on purpose.

    Self-describing — carries its own ``rule_id``/``rule_version``/``tier``
    rather than just ``(verdict, justification, detail)`` — so
    :attr:`EngineOutcome.results` is a complete audit trace by itself,
    without the reviewer needing to cross-reference back to whichever
    :class:`Rule` object produced each entry.
    """

    rule_id: str
    rule_version: str
    tier: EvidenceTier
    verdict: RuleVerdict

    #: Set only when this result proposes clearing a finding: verdict is
    #: SATISFIED and the rule believes the reason may justify NOT_AFFECTED.
    #: Always None for Tier 3 rules and for every non-SATISFIED verdict —
    #: the engine does not trust a justification it finds on a result that
    #: didn't earn it.
    justification: Justification | None = None

    #: Free-form, JSON-serialisable evidence for the reviewer — e.g. which
    #: class path was checked, or the CVSS vector a Tier 3 rule read.
    detail: dict[str, object] = field(default_factory=dict)


@runtime_checkable
class Rule(Protocol):
    """One deterministic check against one component's evidence.

    Implementations never see the other rules that will run, never see
    whether a hard blocker will fire, and never decide the finding's
    overall outcome — that aggregation, and the safety rule it enforces,
    belongs to :class:`RuleEngine` alone. A rule that tried to encode "but
    only if nothing else blocks" would be reimplementing the engine, badly.

    ``tier3_signals`` is passed to every rule, not only Tier 3 ones, so
    every implementation shares one call signature and the engine can treat
    the registry as a uniform list. Tier 1/2 rules simply ignore the
    parameter — they must never read it to decide their own verdict; only
    the engine's own hard-blocker check and Tier 3 rules
    (``app/rules/tier3.py``) are meant to.
    """

    id: str
    version: str
    tier: EvidenceTier

    def evaluate(
        self,
        pack: EvidencePack,
        component: ComponentEvidence,
        tier3_signals: Tier3Signals,
    ) -> RuleEvaluation:
        """Evaluate this rule against one component's evidence.

        Must never raise for missing evidence — return
        ``RuleVerdict.UNANSWERABLE`` instead. An exception here is a bug in
        the rule, not a signal the engine can route anywhere.
        """
        ...


@dataclass(frozen=True, slots=True)
class Tier3Signals:
    """External, per-CVE escalation signals: CVSS, EPSS, KEV, and IQ's own
    reachability call.

    Plainly, for whoever builds Task 4's ``t3-*`` rules against this shape:
    :class:`~app.evidence.pack.EvidencePack` is built by the evidence layer
    from *this artifact* — what ships, what is referenced, what the archive
    contains. CVSS, EPSS and KEV are not that. They come from IQ's
    vulnerability lookup, describe the *CVE itself* rather than this
    artifact, and do not depend on anything the evidence layer inspected.
    Two different systems, on two different cadences, answering two
    different questions — so they arrive through two different channels
    rather than being merged onto one pack.

    These are threaded into :meth:`RuleEngine.evaluate_component` (and from
    there into every :meth:`Rule.evaluate` call) as their own argument
    rather than as fields on ``EvidencePack`` or
    :class:`~app.evidence.pack.ComponentEvidence`. ``EvidencePack``'s own
    docstring defines it as observation of what ships and what is
    referenced; mixing in vendor-supplied risk scoring would blur that
    boundary and make it easy to accidentally wire a Tier 3 field into a
    Tier 1/2 rule's evaluation just because it was reachable off the same
    object.

    This is the shape Task 4's ``app/rules/tier3.py`` (``t3-kev``,
    ``t3-epss``, ``t3-cvss-vector``, ``t3-no-fix-available``) builds
    against — each of those rules reads its field here and reports
    SATISFIED/NOT_SATISFIED/UNANSWERABLE at tier ESCALATION accordingly.

    Every field defaults to the "nothing known" state — ``epss``,
    ``cvss_base_score``, ``cvss_vector``, ``kev``, and ``fix_available`` all
    default to ``None``, never a coerced value, so "not looked up" is never
    silently read as "does not block" (or, for ``fix_available``, "a fix
    exists"). Constructing a bare ``Tier3Signals()`` therefore means "I know
    nothing about this CVE's KEV/EPSS/CVSS/fix status" — which is honest,
    and honest here means the finding routes to a human, not that it clears.

    **``kev``/``fix_available`` are a tri-state ``bool | None``, not a plain
    ``bool`` — fixed across Task 2/3/4's review rounds.** ``None`` means
    "unknown": the vuln lookup for this CVE either was not performed or the
    KEV/fix portion of it failed. This is deliberately distinct from a
    confirmed ``False``, for the same reason ``epss``/``cvss_base_score``
    are ``Optional`` rather than defaulting to ``0``: a caller that read a
    broken or unavailable KEV feed as plain ``False`` would have a silent
    failure present itself as a safe answer — "we could not check KEV" and
    "this is not on KEV" are different facts, and confusing them is exactly
    the failure mode this project has been fighting throughout.

    **Fix round 2: the field *defaults* also moved to ``None``** (round 1
    had widened the type but deliberately left the defaults at their
    pre-existing ``False``/``True`` constants — see the Task 2/3/4 report's
    fix-round-1 section for that reasoning and why it was reconsidered).
    Task 6 builds ``Tier3Signals`` from IQ's vulnerability lookup; a
    response missing its KEV field (a degraded feed, a schema shift, a CVE
    too new to be scored) naturally gets written as
    ``Tier3Signals(epss=..., cvss_vector=...)``, leaving ``kev`` at its
    default. With the old ``False`` default that construction silently
    asserted "this is not a known-exploited vulnerability" — a claim
    nobody made. With ``kev``/``fix_available`` defaulting to ``None``, that
    same construction now honestly says "unknown", and
    ``RuleEngine._hard_blockers`` (for ``kev``) / ``t3-no-fix-available``
    (for ``fix_available``) treat it accordingly. A caller that has
    positively confirmed the safe state must say so explicitly —
    ``Tier3Signals(kev=False)`` / ``Tier3Signals(fix_available=True)`` — a
    permissive outcome is never assumed by omission.
    """

    #: None = "not looked up" (fix round 2 default; see class docstring).
    kev: bool | None = None

    #: EPSS probability, 0-1. None means "not looked up".
    epss: float | None = None

    cvss_base_score: float | None = None

    #: e.g. ``"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"``.
    cvss_vector: str | None = None

    #: IQ's own auto-waiver signal: the violation is reachable with an
    #: observed call path. Distinct from this portal's own Tier 2
    #: constant-pool reference scan
    #: (``ComponentEvidence.referenced``/``reference_scan_conclusive``) —
    #: IQ's reachability analysis sees dynamic call graphs this portal's
    #: static bytecode scan does not.
    #:
    #: ``bool | None``, defaulting to ``None`` — tri-state, mirroring
    #: ``kev``, but with the opposite hard-blocker treatment. ``None``
    #: means "never checked", and today NOTHING in this system checks it:
    #: no adapter, no collector, and no registered Tier 3 rule populates
    #: this field (``RuleEngine._hard_blockers`` reads it directly with no
    #: ``t3-reachable`` rule behind it — see this module's docstring, point
    #: 1). See ``app/rules/registry.py``'s ``PENDING_EVIDENCE`` for this
    #: gap documented alongside the three unregistered rules. Populating it
    #: for real is a Phase 5+ Nexus IQ reachability-analysis integration.
    #:
    #: Unlike ``kev``, ``None`` here does NOT hard-block
    #: (``RuleEngine._hard_blockers`` only blocks on a confirmed ``True``).
    #: This is deliberate, not an oversight: docs/design.md frames IQ's
    #: reachability analysis itself as opt-in and unreliable ("not
    #: dependable enough to act on... opt-in at scan time"), unlike KEV,
    #: which is always looked up. Since nothing populates this field today,
    #: treating ``None`` as blocking would hard-block every single finding
    #: unconditionally forever — not "unresolved input routes to a human",
    #: but "this signal can never clear anything, ever", which defeats the
    #: whole engine rather than protecting it. ``False`` still means exactly
    #: what it always meant: "IQ confirmed a call path was not found" — and
    #: nothing produces that value yet either, which is exactly why the type
    #: must be able to say ``None`` instead of a caller (or this dataclass's
    #: own bare default) asserting it on nothing.
    reachable_with_call_path: bool | None = None

    #: Whether a fix is available for this CVE at this component's version.
    #: Read by ``t3-no-fix-available`` (Task 4); not itself a hard blocker —
    #: unlike ``kev``, ``None`` here ("unknown") does not add to
    #: ``blocked_by``; it only makes ``t3-no-fix-available`` report
    #: UNANSWERABLE. See the class docstring's tri-state note.
    fix_available: bool | None = None


@dataclass(frozen=True, slots=True)
class EngineOutcome:
    """What the engine proposes for one component, and the full trace of
    every rule that ran."""

    proposed: FindingOutcome

    #: The tier that decided ``proposed``, when it is NOT_AFFECTED. None
    #: otherwise — including for NEEDS_REVIEW, where no single tier "won".
    tier: EvidenceTier | None

    #: The justification that decided ``proposed``, when it is NOT_AFFECTED.
    #: None otherwise.
    justification: Justification | None

    #: True when the deciding tier was STRONG (Tier 2): defeasible evidence
    #: that must not auto-clear without an independent second-confirmation
    #: pass. Always False when ``proposed`` is not NOT_AFFECTED.
    requires_second_confirmation: bool

    #: Which hard blocker(s) fired: any of ``"kev"``, ``"reachable"``,
    #: ``"epss"``, ``"cvss"``. Empty when none did — including when
    #: ``proposed`` is NEEDS_REVIEW for a different reason (an UNANSWERABLE
    #: rule, or simply no rule cleared), so an empty set here is not proof
    #: that nothing routed the finding to review.
    blocked_by: frozenset[str]

    #: Every rule that ran, in registration order, regardless of its
    #: verdict. The reviewer's trust surface and the audit record.
    results: tuple[RuleEvaluation, ...]


class RuleEngine:
    """Runs every registered rule against a component and aggregates the
    results under the tier safety rule. See the module docstring for the
    full priority order.
    """

    def __init__(self, rules: Sequence[Rule], *, epss_threshold: float = 0.10) -> None:
        """Args:
            rules: the rules to run, in the order they should be recorded in
                the trace.
            epss_threshold: EPSS probability at or above which the EPSS
                hard blocker fires. Defaults to 0.10, matching the
                admin-configurable default shown in
                docs/design/ui-mockups.html's "EPSS routing threshold"
                field. Per app/config.py's rule that behaviour tunables are
                team decisions that live in the database, a later task
                should thread the persisted value in here rather than
                relying on this default in production.
        """
        self._rules = tuple(rules)
        self._epss_threshold = epss_threshold

    def evaluate_component(
        self,
        pack: EvidencePack,
        component: ComponentEvidence,
        tier3_signals: Tier3Signals | None = None,
    ) -> EngineOutcome:
        """Run every registered rule against ``component`` and propose one
        outcome.

        ``tier3_signals`` is optional so a caller with no vuln enrichment
        yet still gets a valid, blocker-free outcome rather than being
        forced to construct a placeholder. Omit it only when Tier 3 lookup
        is genuinely unavailable, not as a routine shortcut — a missing
        KEV/EPSS/CVSS lookup means the hard blockers below silently cannot
        fire, which is a real gap in the determination, not a neutral one.
        """
        signals = tier3_signals if tier3_signals is not None else Tier3Signals()
        results = tuple(rule.evaluate(pack, component, signals) for rule in self._rules)

        blocked_by = self._hard_blockers(signals)
        unanswerable = any(result.verdict is RuleVerdict.UNANSWERABLE for result in results)
        clearing = self._best_clearing_result(results)

        if blocked_by or unanswerable or clearing is None:
            return EngineOutcome(
                proposed=FindingOutcome.NEEDS_REVIEW,
                tier=None,
                justification=None,
                requires_second_confirmation=False,
                blocked_by=blocked_by,
                results=results,
            )

        return EngineOutcome(
            proposed=FindingOutcome.NOT_AFFECTED,
            tier=clearing.tier,
            justification=clearing.justification,
            requires_second_confirmation=clearing.tier.requires_second_confirmation(),
            blocked_by=blocked_by,
            results=results,
        )

    @staticmethod
    def _best_clearing_result(results: Sequence[RuleEvaluation]) -> RuleEvaluation | None:
        """The strongest rule result that may justify NOT_AFFECTED, if any.

        "Strongest" means the lowest ``EvidenceTier`` value — PROOF (1)
        beats STRONG (2) — favouring the least defeasible evidence
        available.
        """
        candidates = [
            result
            for result in results
            if result.verdict is RuleVerdict.SATISFIED
            and result.tier.may_justify()
            and result.justification is not None
            and result.justification.justifies_determination()
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda result: result.tier)

    def _hard_blockers(self, signals: Tier3Signals) -> frozenset[str]:
        blockers: set[str] = set()
        # Unknown KEV status blocks exactly like confirmed KEV: an outage or
        # failure in the KEV feed must not quietly re-enable auto-clearing
        # for the vulnerabilities most likely to be exploited. Only a
        # positively-confirmed `False` skips the block — see Tier3Signals'
        # docstring's tri-state note.
        if signals.kev is None or signals.kev:
            blockers.add("kev")
        # Deliberately the OPPOSITE unknown-handling from kev: only a
        # positively-confirmed True blocks. Nothing in this system
        # populates this field today (see Tier3Signals.reachable_with_call_path's
        # own docstring and app/rules/registry.py's PENDING_EVIDENCE) — since
        # every finding would otherwise construct a bare/default Tier3Signals,
        # treating `None` as blocking here would hard-block every finding
        # unconditionally, forever, rather than routing an unresolved input to
        # a human. `is True` (not truthy `if signals.reachable_with_call_path:`)
        # makes that choice explicit rather than an accident of None/False
        # both being falsy.
        if signals.reachable_with_call_path is True:
            blockers.add("reachable")
        if signals.epss is not None and signals.epss >= self._epss_threshold:
            blockers.add("epss")
        if self._cvss_blocks(signals):
            blockers.add("cvss")
        return frozenset(blockers)

    @staticmethod
    def _cvss_blocks(signals: Tier3Signals) -> bool:
        """Whether the CVSS hard blocker fires: base score >= 9 AND the
        vector is unauthenticated, no-user-interaction, over the network
        (``AV:N/PR:N/UI:N``).

        A score with no parseable vector does not block on the score alone
        — the blocker is specifically about *that* exploitability shape,
        not high severity in general, and a local-only CVSS 9.8 is exactly
        the case the AV:N/PR:N/UI:N clause exists to exclude. A missing or
        malformed vector is treated the same as "vector says no" rather
        than "assume the worst"; in practice IQ's vuln lookup supplies a
        vector alongside every base score it reports, so this only matters
        for an incomplete or synthetic ``Tier3Signals``.
        """
        if signals.cvss_base_score is None or signals.cvss_base_score < _CVSS_BLOCK_SCORE:
            return False
        metrics = _parse_cvss_vector(signals.cvss_vector)
        return metrics.get("AV") == "N" and metrics.get("PR") == "N" and metrics.get("UI") == "N"


def _parse_cvss_vector(vector: str | None) -> dict[str, str]:
    """Split a CVSS vector string into its metric abbreviations.

    Tolerant of the leading ``CVSS:3.1`` prefix segment (harmless —
    ``metrics["CVSS"] = "3.1"``, never looked up) and of ``None`` or
    malformed input, both of which yield an empty mapping rather than
    raising.
    """
    if not vector:
        return {}
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        key, sep, value = part.partition(":")
        if sep:
            metrics[key] = value
    return metrics
