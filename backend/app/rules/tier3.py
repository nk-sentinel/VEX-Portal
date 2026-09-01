"""Tier 3 rules: escalation only — never a clearance.

Every rule here reports at ``EvidenceTier.ESCALATION`` and never sets
``justification`` on a ``RuleEvaluation``. Both are structural, not a
convention this module could get wrong and still slip through:
``EvidenceTier.may_justify()`` is False for ESCALATION, so
``RuleEngine._best_clearing_result`` cannot select a Tier 3 result as a
clearing candidate regardless of its verdict, and
``RuleEvaluation.justification`` is documented as "Always None for Tier 3
rules" (``app/rules/engine.py``). App context — exposure, criticality,
network position — is not reliably available in this environment and is
attacker-influenced; by policy (CLAUDE.md rule 2, docs/design.md "Tier 3 —
escalation only") it may only raise severity or route a finding to a human,
never justify Not Affected. This module has two behaviours only: signal a
reviewer-visible fact (SATISFIED/NOT_SATISFIED), or say it cannot answer
(UNANSWERABLE) — and even a SATISFIED verdict here can never, on its own,
move ``EngineOutcome.proposed`` away from ``NEEDS_REVIEW``.

**``t3-no-fix-available`` is special, not a determination.** Per CLAUDE.md
rule 5: no fix available routes the case to ``RISK_ACCEPTANCE_REQUIRED``,
handled by the app team with their risk manager, out of band — nothing is
committed to IQ, and the IQ violation stays OPEN. This rule does not itself
assign ``RISK_ACCEPTANCE_REQUIRED``: per ``app/rules/engine.py``'s own
docstring (priority order, point 4), that routing decision belongs to the
determination service (Phase 4, Task 8), made by inspecting
``EngineOutcome.results`` for a SATISFIED ``t3-no-fix-available`` entry one
layer above this module's aggregation step. This rule's only job is to make
that fact appear in the trace.

**All four rules now support UNANSWERABLE (fix round 1).** ``Tier3Signals.kev``
and ``fix_available`` were originally plain ``bool`` fields with safe
defaults (``False``/``True``); Task 1's own reasoning for that shape was
"nothing known" reading as "no blocker implied", which seemed like the safe
direction because Tier 3 evidence can only ever escalate, never clear. The
coordinator's fix round 1 review correctly identified the hazard that logic
missed: a lookup that never ran (or a KEV feed outage) was indistinguishable
from a lookup that positively confirmed the safe answer — "we could not
check KEV" and "this is not on KEV" are different facts, and a rule that
conflates them is a silent failure presenting as a safe answer. Both fields
are now ``bool | None`` (``None`` = unknown); see ``Tier3Signals``'s own
docstring for the full tri-state note, including why the field *default*
was deliberately left unchanged (a judgment call flagged in the Task 2/3/4
report). ``t3-kev`` and ``t3-no-fix-available`` now report UNANSWERABLE on
``None`` exactly like ``t3-epss``/``t3-cvss-vector`` do on their own
``Optional`` fields. The one remaining asymmetry: unknown KEV is also a
hard *blocker* (``RuleEngine._hard_blockers`` treats ``kev is None`` the
same as ``kev is True``) — "if we cannot establish KEV status, a human
decides" — while unknown ``fix_available`` is not, matching
``fix_available``'s pre-existing non-blocking role.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.domain.determination import EvidenceTier
from app.evidence.pack import ComponentEvidence, EvidencePack
from app.rules.engine import RuleEvaluation, RuleVerdict, Tier3Signals

#: Mirrors RuleEngine's own default EPSS routing threshold
#: (docs/design/ui-mockups.html, "EPSS routing threshold", default 0.10). NOT
#: the same object as RuleEngine._epss_threshold, which is a configurable
#: constructor parameter — if a later task threads a persisted,
#: admin-configurable value into RuleEngine, this constant will silently stop
#: matching it unless updated in lockstep. This rule's SATISFIED verdict is
#: audit-trail signal, not itself a hard blocker (the engine's own
#: _hard_blockers reads Tier3Signals.epss directly, independent of whether
#: this rule is even registered) — so drift here changes what the trace
#: records, not whether the engine actually blocks. Flagged in the Task
#: 2/3/4 report regardless, since a diverged number in an audit trail is
#: still a defect a reviewer would trip over.
_EPSS_SIGNAL_THRESHOLD = 0.10

#: CVSS "High" severity floor, per the CVSS spec's own qualitative rating
#: bands (0-3.9 Low, 4-6.9 Medium, 7-8.9 High, 9-10 Critical) — a stable,
#: spec-defined number, deliberately NOT the same as
#: RuleEngine._CVSS_BLOCK_SCORE's hard-blocker floor (9.0). This rule is a
#: weaker, broader escalation signal than the engine's hard blocker on
#: purpose: it flags a notable exploitability shape (unauthenticated,
#: no user interaction, over the network) at "High" severity, so it also
#: catches e.g. a CVSS 7.5 AV:N/PR:N/UI:N vector the hard blocker (score >=
#: 9 required) would not.
_CVSS_HIGH_SCORE = 7.0


def _make(
    rule_id: str,
    rule_version: str,
    verdict: RuleVerdict,
    *,
    detail: dict[str, object] | None = None,
) -> RuleEvaluation:
    """Build one ESCALATION-tier :class:`RuleEvaluation` with no justification.

    Every rule in this module is ``EvidenceTier.ESCALATION`` and never sets
    ``justification`` — baked into this helper's signature (no
    ``justification`` parameter at all) rather than left to each call site to
    remember, so a future edit cannot accidentally hand a Tier 3 rule a
    clearing justification.
    """
    return RuleEvaluation(
        rule_id=rule_id,
        rule_version=rule_version,
        tier=EvidenceTier.ESCALATION,
        verdict=verdict,
        justification=None,
        detail=detail if detail is not None else {},
    )


def _parse_cvss_vector(vector: str) -> dict[str, str]:
    """Split a CVSS vector string into its metric abbreviations.

    Same tolerant slash/colon parsing as ``RuleEngine._parse_cvss_vector``
    (``app/rules/engine.py``), duplicated locally rather than imported: that
    function is module-private there (leading underscore), and CVSS's vector
    syntax is a stable, spec-defined format unlikely to need independent
    evolution here.
    """
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        key, sep, value = part.partition(":")
        if sep:
            metrics[key] = value
    return metrics


@dataclass(slots=True)
class Kev:
    """``t3-kev``: IQ's own vuln lookup flags this CVE as a known,
    actively-exploited vulnerability (CISA KEV).

    This rule's own verdict does not itself drive hard-blocking behaviour —
    ``RuleEngine._hard_blockers`` reads ``Tier3Signals.kev`` directly,
    independent of whether this rule is registered at all (see
    ``app/rules/engine.py``'s module docstring, priority order point 1). This
    rule exists so the fact appears explicitly in the audit trace
    (``EngineOutcome.results``) rather than only implicitly through
    ``blocked_by``.

    UNANSWERABLE when ``tier3_signals.kev is None`` — "unknown", not
    "confirmed not KEV" (fix round 1: see the module docstring's tri-state
    note). ``RuleEngine._hard_blockers`` treats this same ``None`` state as
    a hard blocker, identically to ``kev=True``: an unresolved KEV lookup
    must route to a human, never silently permit an auto-clear.
    """

    id: str = field(default="t3-kev", init=False)
    version: str = field(default="1", init=False)
    tier: EvidenceTier = field(default=EvidenceTier.ESCALATION, init=False)

    def evaluate(
        self,
        pack: EvidencePack,
        component: ComponentEvidence,
        tier3_signals: Tier3Signals,
    ) -> RuleEvaluation:
        del pack
        if tier3_signals.kev is None:
            return _make(
                self.id,
                self.version,
                RuleVerdict.UNANSWERABLE,
                detail={"cve": component.cve, "reason": "kev not looked up"},
            )
        verdict = RuleVerdict.SATISFIED if tier3_signals.kev else RuleVerdict.NOT_SATISFIED
        return _make(
            self.id,
            self.version,
            verdict,
            detail={"cve": component.cve, "kev": tier3_signals.kev},
        )


@dataclass(slots=True)
class Epss:
    """``t3-epss``: signals an elevated EPSS exploitation-probability score.

    UNANSWERABLE when ``tier3_signals.epss is None`` — "not looked up", per
    ``Tier3Signals``'s own docstring, distinct from a genuine ``0.0`` score.
    SATISFIED at or above ``_EPSS_SIGNAL_THRESHOLD`` — see that constant's
    comment for the drift risk against ``RuleEngine``'s own configurable
    hard-blocker threshold.
    """

    id: str = field(default="t3-epss", init=False)
    version: str = field(default="1", init=False)
    tier: EvidenceTier = field(default=EvidenceTier.ESCALATION, init=False)

    def evaluate(
        self,
        pack: EvidencePack,
        component: ComponentEvidence,
        tier3_signals: Tier3Signals,
    ) -> RuleEvaluation:
        del pack
        if tier3_signals.epss is None:
            return _make(
                self.id,
                self.version,
                RuleVerdict.UNANSWERABLE,
                detail={"cve": component.cve, "reason": "epss not looked up"},
            )
        verdict = (
            RuleVerdict.SATISFIED
            if tier3_signals.epss >= _EPSS_SIGNAL_THRESHOLD
            else RuleVerdict.NOT_SATISFIED
        )
        return _make(
            self.id,
            self.version,
            verdict,
            detail={"cve": component.cve, "epss": tier3_signals.epss},
        )


@dataclass(slots=True)
class CvssVector:
    """``t3-cvss-vector``: signals a CVSS vector shape worth a reviewer's
    attention — unauthenticated, no user interaction, over the network
    (``AV:N/PR:N/UI:N``) at CVSS "High" (``>= 7.0``) or above.

    Deliberately a weaker, broader bar than ``RuleEngine``'s own CVSS hard
    blocker (score ``>= 9.0`` AND the same vector shape): this rule surfaces
    a notable exploitability shape into the audit trace even when it does
    not clear the engine's automatic-review bar. See ``_CVSS_HIGH_SCORE``'s
    comment.

    UNANSWERABLE when either ``cvss_vector`` or ``cvss_base_score`` is
    ``None`` — this rule's condition needs both, and either one being
    unlooked-up means the compound condition cannot be evaluated.
    """

    id: str = field(default="t3-cvss-vector", init=False)
    version: str = field(default="1", init=False)
    tier: EvidenceTier = field(default=EvidenceTier.ESCALATION, init=False)

    def evaluate(
        self,
        pack: EvidencePack,
        component: ComponentEvidence,
        tier3_signals: Tier3Signals,
    ) -> RuleEvaluation:
        del pack
        vector = tier3_signals.cvss_vector
        score = tier3_signals.cvss_base_score
        if vector is None or score is None:
            return _make(
                self.id,
                self.version,
                RuleVerdict.UNANSWERABLE,
                detail={
                    "cve": component.cve,
                    "reason": "cvss_vector or cvss_base_score not looked up",
                },
            )
        metrics = _parse_cvss_vector(vector)
        notable_shape = (
            metrics.get("AV") == "N" and metrics.get("PR") == "N" and metrics.get("UI") == "N"
        )
        verdict = (
            RuleVerdict.SATISFIED
            if notable_shape and score >= _CVSS_HIGH_SCORE
            else RuleVerdict.NOT_SATISFIED
        )
        return _make(
            self.id,
            self.version,
            verdict,
            detail={"cve": component.cve, "cvss_vector": vector, "cvss_base_score": score},
        )


@dataclass(slots=True)
class NoFixAvailable:
    """``t3-no-fix-available``: SATISFIED when no remediation exists for this
    CVE at this component's version.

    **Special: a hand-off, never a determination.** See the module
    docstring's "``t3-no-fix-available`` is special" section — this rule only
    makes the fact appear in the trace; the ``RISK_ACCEPTANCE_REQUIRED``
    routing itself is the determination service's job (Task 8), not this
    engine's or this rule's.

    UNANSWERABLE when ``tier3_signals.fix_available is None`` — "unknown",
    not "confirmed a fix exists" (fix round 1: see the module docstring's
    tri-state note). Unlike ``t3-kev``, unknown ``fix_available`` is NOT a
    hard blocker: ``fix_available`` never was one, and that has not
    changed — only its ability to express "unknown" at all has.
    """

    id: str = field(default="t3-no-fix-available", init=False)
    version: str = field(default="1", init=False)
    tier: EvidenceTier = field(default=EvidenceTier.ESCALATION, init=False)

    def evaluate(
        self,
        pack: EvidencePack,
        component: ComponentEvidence,
        tier3_signals: Tier3Signals,
    ) -> RuleEvaluation:
        del pack
        if tier3_signals.fix_available is None:
            return _make(
                self.id,
                self.version,
                RuleVerdict.UNANSWERABLE,
                detail={"cve": component.cve, "reason": "fix_available not looked up"},
            )
        verdict = (
            RuleVerdict.NOT_SATISFIED
            if tier3_signals.fix_available
            else RuleVerdict.SATISFIED
        )
        return _make(
            self.id,
            self.version,
            verdict,
            detail={"cve": component.cve, "fix_available": tier3_signals.fix_available},
        )
