"""Combine rule-engine output and (where needed) an AI verdict into exactly
one of the four terminal outcomes, persist it, and commit ``NOT_AFFECTED``
to Nexus IQ.

**Priority order** (mirrors ``app/rules/engine.py``'s own priority order one
layer up, plus CLAUDE.md rules 2 and 5):

1. The rule engine already cleared the finding
   (``EngineOutcome.proposed is FindingOutcome.NOT_AFFECTED``, which is only
   possible when ``blocked_by`` is empty — the engine itself guarantees
   this, see its module docstring point 1):

   a. Tier 1 (PROOF): commit ``NOT_AFFECTED`` directly. No AI call — proof
      needs no confirmation, and this is the majority path docs/design.md's
      "Intended outcome" describes as resolving "deterministically with no
      AI and no human".
   b. Tier 2 (STRONG): defeasible evidence, per docs/design.md's own rule —
      "Auto-determination only with independent second confirmation". The
      AI adjudicator (``app.services.adjudication.adjudicate_finding``) is
      that confirmation. Agreement commits ``NOT_AFFECTED`` at tier STRONG;
      disagreement or abstention routes to ``NEEDS_REVIEW``.

2. The rule engine could not clear it (``proposed is NEEDS_REVIEW``):

   a. **A hard blocker is absolute and is checked before anything else in
      this branch, without ever asking the AI.** ``EngineOutcome.blocked_by``
      non-empty (KEV, reachable-with-call-path, EPSS, CVSS) always routes to
      ``NEEDS_REVIEW`` — this must not be skippable by an AI verdict, because
      the adjudicator's prompt deliberately excludes Tier 3 signals
      (``app/adapters/llm/client.py``'s ``_build_prompt`` — CVSS/EPSS/KEV
      never reach the model, so the AI is blind to a hard blocker and could
      otherwise be talked into confidently clearing a KEV finding it never
      saw evidence of).
   b. **No fix available is checked next, and also skips the AI entirely.**
      A ``t3-no-fix-available`` SATISFIED result in the trace routes to
      ``RISK_ACCEPTANCE_REQUIRED`` — CLAUDE.md rule 5: this is never a
      ``NOT_AFFECTED`` determination, full stop, regardless of what an AI
      might otherwise conclude. Nothing is sent to IQ; the violation stays
      open. (Note this branch is unreachable when a Tier 1/2 rule already
      cleared the finding via branch 1 above — the sample scenario's
      CVE-2015-6420 has *both* a Tier 1 proof of absence *and* no fix
      available, and Tier 1 proof wins, per fakes/README.md's own
      description of that case.)
   c. Otherwise: the constrained middle band. The AI adjudicator decides —
      abstention or refute-disagreement routes to ``NEEDS_REVIEW``; a
      confirmed clear commits ``NOT_AFFECTED`` at tier STRONG (AI reasoning
      is inherently defeasible, never PROOF); a confident reject commits
      ``AFFECTED`` with nothing sent to IQ (the safe direction — nothing is
      suppressed, so no extra confirmation is required, mirroring "auto-reject
      needs no refute pass" from the adjudication service).

**``Determination.validate()`` is the last gate**, called immediately before
anything is persisted or sent to IQ — never after. See
:func:`build_not_affected_determination`.

**The IQ suppression id comes from a follow-up read, not the create call.**
``IqClient.create_determination`` already implements this (IQ's waiver
create returns ``204 No Content``); if it cannot resolve an id it raises
``DeterminationIdUnresolved``, which this module does not catch — a
determination whose id cannot be established can never be revoked or
audited, and ``iq_determination_link.policy_waiver_id`` is non-nullable.

**Every transition writes an ``audit_entry``.**

**Bridging ``RuleEvaluation`` to ``RuleResult`` — a lossy bridge, not an
equivalence.** ``app.repos.models.RuleResult.verdict`` is typed
``Mapped[State]``, and its own docstring says "a rule's verdict is exactly a
proposed State". But ``app.rules.engine.RuleEvaluation.verdict`` is a
``RuleVerdict`` (SATISFIED / NOT_SATISFIED / INAPPLICABLE / UNANSWERABLE) —
a rule's judgement about its own condition — which is a different
vocabulary at a different layer than ``State`` (NOT_AFFECTED / AFFECTED /
UNDER_INVESTIGATION) — a finding's VEX disposition. Only
SATISFIED-with-a-clearing-justification has an unambiguous ``State``
counterpart. See :func:`_bridge_rule_verdict_to_state` for the mapping
chosen and why the raw ``RuleVerdict`` is preserved verbatim in
``detail_json`` alongside it — flagged in full in the Task 5-8 report as a
schema/domain mismatch this module works around rather than one it can fix
(fixing it would mean an ``app/repos/models.py`` column-type change and a
migration, outside this task's file scope).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.protocols import Adjudicator, DeterminationOptions, FindingRef, IqClient
from app.domain.determination import (
    Confidence,
    Determination,
    DeterminationError,
    EvidenceTier,
    Justification,
    State,
)
from app.evidence.pack import EvidencePack
from app.repos.models import AiVerdict as AiVerdictRow
from app.repos.models import (
    Assessment,
    AuditEntry,
    Finding,
    FindingOutcome,
    IqDeterminationLink,
    RuleResult,
)
from app.rules.engine import EngineOutcome, RuleEvaluation, RuleVerdict
from app.services.adjudication import AdjudicationResult, adjudicate_finding

#: Determinations expire at 7 days and are never auto-renewed (CLAUDE.md
#: rule 4) — all branches scan into the same IQ application, so a
#: determination made against one branch cannot be assumed valid for
#: another.
_EXPIRY = timedelta(days=7)

_NO_FIX_AVAILABLE_RULE_ID = "t3-no-fix-available"


def build_not_affected_determination(
    *,
    tier: EvidenceTier,
    justification: Justification,
    confidence: Confidence,
    evidence_refs: tuple[str, ...],
    missing_evidence: tuple[str, ...] = (),
) -> Determination:
    """Build a ``NOT_AFFECTED`` :class:`Determination` and validate it —
    exposed separately from :func:`determine` so the last gate itself is
    directly testable in isolation from the full rule-engine/adjudication
    pipeline that, when well-formed, can never actually produce an invalid
    combination (the engine only ever selects a clearing rule whose tier
    and justification are already valid — see ``app/rules/engine.py``'s
    ``_best_clearing_result``).

    Raises:
        DeterminationError: the combination does not satisfy
            ``Determination.validate()`` — tier cannot justify a clear, the
            justification does not, or no evidence reference was supplied.
    """
    determination = Determination(
        state=State.NOT_AFFECTED,
        tier=tier,
        confidence=confidence,
        justification=justification,
        evidence_refs=evidence_refs,
        missing_evidence=missing_evidence,
    )
    determination.validate()
    return determination


def _no_fix_available(engine_outcome: EngineOutcome) -> bool:
    return any(
        result.rule_id == _NO_FIX_AVAILABLE_RULE_ID and result.verdict is RuleVerdict.SATISFIED
        for result in engine_outcome.results
    )


def _rule_evidence_refs(engine_outcome: EngineOutcome, cve: str) -> tuple[str, ...]:
    """Evidence references for a rule-decided clear: the deciding rule(s) —
    those matching the tier and justification the engine actually picked.
    Falls back to a generic reference if, somehow, none match (should not
    happen for a well-formed ``EngineOutcome``, but ``evidence_refs`` must
    never come back empty for a proposed NOT_AFFECTED — ``Determination.validate``
    would reject that, and it is better to be defensive here than to
    manufacture that failure from a construction bug in this module).
    """
    deciding = [
        result
        for result in engine_outcome.results
        if result.verdict is RuleVerdict.SATISFIED
        and result.tier is engine_outcome.tier
        and result.justification is engine_outcome.justification
    ]
    refs = tuple(f"rule:{result.rule_id}:{result.rule_version}:{cve}" for result in deciding)
    return refs or (f"rule:unknown:{cve}",)


def _bridge_rule_verdict_to_state(evaluation: RuleEvaluation) -> State:
    """Map one rule's ``RuleVerdict`` onto the ``State`` value
    ``RuleResult.verdict`` requires. See this module's docstring for why
    this is necessarily lossy.

    - SATISFIED with a clearing justification: the rule is proposing the
      finding is not affected -> ``State.NOT_AFFECTED``.
    - SATISFIED with no justification (a Tier 3 escalation signal, or
      ``t3-no-fix-available``): the condition held, but this was never a
      clearing signal -> ``State.UNDER_INVESTIGATION``, the closest "needs
      attention" value ``State`` has.
    - NOT_SATISFIED: for a Tier 1/2 rule this means the vulnerable condition
      held (the class is present, referenced, etc.), pointing toward the
      finding applying -> ``State.AFFECTED``. Imprecise for a Tier 3 rule's
      reassuring NOT_SATISFIED (e.g. "not KEV") — another reason the raw
      verdict is preserved in ``detail_json`` alongside this value.
    - INAPPLICABLE / UNANSWERABLE: the rule did not or could not judge this
      case -> ``State.UNDER_INVESTIGATION``.
    """
    if evaluation.verdict is RuleVerdict.SATISFIED and evaluation.justification is not None:
        return State.NOT_AFFECTED
    if evaluation.verdict is RuleVerdict.NOT_SATISFIED:
        return State.AFFECTED
    return State.UNDER_INVESTIGATION


def _persist_rule_results(
    session: AsyncSession, finding_id: str, engine_outcome: EngineOutcome
) -> None:
    """Persist the full rule trace, regardless of outcome — the reviewer's
    trust surface and the audit record (``app/rules/engine.py``'s own
    docstring)."""
    for evaluation in engine_outcome.results:
        detail = dict(evaluation.detail)
        # The raw RuleVerdict, preserved verbatim: see this module's
        # docstring on the lossy RuleEvaluation -> RuleResult bridge.
        detail["rule_verdict"] = evaluation.verdict.value
        session.add(
            RuleResult(
                finding_id=finding_id,
                rule_id=evaluation.rule_id,
                rule_version=evaluation.rule_version,
                verdict=_bridge_rule_verdict_to_state(evaluation),
                tier=evaluation.tier,
                detail_json=detail,
            )
        )


def _persist_ai_verdict(
    session: AsyncSession,
    finding_id: str,
    *,
    model_id: str,
    prompt_version: str,
    ai_result: AdjudicationResult,
) -> None:
    session.add(
        AiVerdictRow(
            finding_id=finding_id,
            model_id=model_id,
            prompt_version=prompt_version,
            state=ai_result.verdict.state,
            justification=ai_result.verdict.justification,
            confidence=ai_result.verdict.confidence,
            evidence_refs_json=list(ai_result.verdict.evidence_refs),
            missing_evidence_json=list(ai_result.verdict.missing_evidence),
            # Records that an independent refute pass ran, not just that
            # this row's own call happened — required before a Tier 2/AI
            # clear may auto-determine (docs/design.md, "Second refute-pass
            # on any auto-Not Affected path").
            refuted_by=(prompt_version if ai_result.refute_verdict is not None else None),
        )
    )


def _persist_audit_entry(
    session: AsyncSession,
    *,
    assessment: Assessment,
    finding: Finding,
    outcome: FindingOutcome,
    tier: EvidenceTier | None,
    justification: Justification | None,
    confidence: Confidence | None,
    engine_outcome: EngineOutcome,
    actor: str,
) -> None:
    session.add(
        AuditEntry(
            actor=actor,
            action=f"finding.determined.{outcome.value}",
            subject_type="finding",
            subject_id=finding.id,
            detail_json={
                "assessment_id": assessment.id,
                "cve": finding.cve,
                "purl": finding.purl,
                "tier": tier.value if tier is not None else None,
                "justification": justification.value if justification is not None else None,
                "confidence": confidence.value if confidence is not None else None,
                "blocked_by": sorted(engine_outcome.blocked_by),
            },
        )
    )


async def determine(
    finding: Finding,
    assessment: Assessment,
    engine_outcome: EngineOutcome,
    pack: EvidencePack,
    *,
    session: AsyncSession,
    iq: IqClient,
    adjudicator: Adjudicator,
    actor: str,
    model_id: str = "adjudicator",
    prompt_version: str = "v1",
) -> Finding:
    """Combine ``engine_outcome`` and (where needed) an AI verdict into one
    of the four terminal outcomes, persist it, and commit ``NOT_AFFECTED``
    to Nexus IQ.

    **Hard blockers are resolved before the AI is ever consulted, and this
    is load-bearing, not a redundant-looking early return.** The adjudicator
    is blind to hard blockers, not merely forbidden from using them: its
    prompt (``app/adapters/llm/client.py``'s ``_build_prompt``) never
    includes CVSS, EPSS, or KEV at all, so a model that has never seen
    evidence of a KEV finding could still confidently propose
    ``NOT_AFFECTED`` for one. Checking ``engine_outcome.blocked_by`` first —
    before the "otherwise, ask the AI" branch even runs — is the only
    ordering under which a hard-blocked finding can never reach the model in
    the first place. If a future edit moves this check to run *after*
    consulting the AI (e.g. to "only override an AI clear"), it reopens
    exactly the gap this ordering exists to close: the sample scenario's own
    KEV finding (CVE-2022-42889) would sail past this check unnoticed
    because the AI was never shown a reason to say anything but
    ``NOT_AFFECTED``.

    Args:
        finding: the persisted ``Finding`` row for this (CVE, purl) case.
            Mutated in place with the decided outcome.
        assessment: the persisted ``Assessment`` row ``finding`` belongs to
            (for ``application_id`` and the IQ determination's rationale).
        engine_outcome: the deterministic rule engine's proposal for this
            finding's component.
        pack: the evidence pack, passed through to the adjudicator when the
            AI is consulted.
        session: the database session. This function flushes but does not
            commit — the caller owns the transaction boundary.
        iq: the Nexus IQ client, for the ``NOT_AFFECTED`` commit.
        adjudicator: the AI adjudicator, consulted only when the rule engine
            did not already produce a Tier 1 (PROOF) clear.
        actor: who/what made this determination, for the audit entry and
            ``Finding.decided_by``.

    Returns:
        The same ``finding`` object, mutated with the decided outcome.

    Raises:
        DeterminationError: the combination that would be committed does
            not satisfy ``Determination.validate()``.
        DeterminationIdUnresolved: (from ``iq.create_determination``) the IQ
            waiver was created but its id could not be established. Not
            caught here — propagated, per this module's docstring.
    """
    finding_ref = FindingRef(
        application_id=assessment.application_id, cve=finding.cve, purl=finding.purl
    )

    outcome: FindingOutcome
    tier: EvidenceTier | None = None
    justification: Justification | None = None
    confidence: Confidence | None = None
    evidence_refs: tuple[str, ...] = ()
    ai_result: AdjudicationResult | None = None

    if engine_outcome.proposed is FindingOutcome.NOT_AFFECTED:
        # Only possible when blocked_by is empty (app/rules/engine.py
        # guarantees this), and only when a rule of tier PROOF or STRONG
        # was satisfied with a justifying justification.
        assert engine_outcome.tier is not None
        assert engine_outcome.justification is not None

        if engine_outcome.tier is EvidenceTier.PROOF:
            outcome = FindingOutcome.NOT_AFFECTED
            tier = EvidenceTier.PROOF
            justification = engine_outcome.justification
            # Deterministic proof, not a self-reported AI certainty — HIGH
            # is the closest Confidence analogue; Tier 1 proof is strictly
            # stronger evidence than any AI verdict this system produces.
            confidence = Confidence.HIGH
            evidence_refs = _rule_evidence_refs(engine_outcome, finding.cve)
        else:
            # Tier 2 (STRONG): defeasible, needs independent confirmation.
            ai_result = await adjudicate_finding(
                pack, finding_ref, adjudicator=adjudicator, iq=iq, session=session
            )
            if not ai_result.requires_review and ai_result.verdict.state is State.NOT_AFFECTED:
                outcome = FindingOutcome.NOT_AFFECTED
                tier = EvidenceTier.STRONG
                justification = engine_outcome.justification
                confidence = ai_result.verdict.confidence
                evidence_refs = tuple(ai_result.verdict.evidence_refs) or _rule_evidence_refs(
                    engine_outcome, finding.cve
                )
            else:
                outcome = FindingOutcome.NEEDS_REVIEW
    elif engine_outcome.blocked_by:
        # A hard blocker is absolute: never ask the AI, which is blind to
        # Tier 3 signals by construction — see this module's docstring.
        outcome = FindingOutcome.NEEDS_REVIEW
    elif _no_fix_available(engine_outcome):
        # CLAUDE.md rule 5: never a NOT_AFFECTED determination, and never
        # asked of the AI — nothing is sent to IQ, the violation stays open.
        outcome = FindingOutcome.RISK_ACCEPTANCE_REQUIRED
    else:
        ai_result = await adjudicate_finding(
            pack, finding_ref, adjudicator=adjudicator, iq=iq, session=session
        )
        if ai_result.requires_review:
            outcome = FindingOutcome.NEEDS_REVIEW
        elif ai_result.verdict.state is State.NOT_AFFECTED:
            outcome = FindingOutcome.NOT_AFFECTED
            tier = EvidenceTier.STRONG
            justification = ai_result.verdict.justification
            confidence = ai_result.verdict.confidence
            evidence_refs = tuple(ai_result.verdict.evidence_refs)
        elif ai_result.verdict.state is State.AFFECTED:
            outcome = FindingOutcome.AFFECTED
            confidence = ai_result.verdict.confidence
        else:  # pragma: no cover - defensive; adjudicate_finding already
            # routes UNDER_INVESTIGATION through requires_review above.
            outcome = FindingOutcome.NEEDS_REVIEW

    if outcome is FindingOutcome.NOT_AFFECTED:
        assert tier is not None
        assert justification is not None
        assert confidence is not None
        # The last gate — called before anything is persisted or sent.
        build_not_affected_determination(
            tier=tier,
            justification=justification,
            confidence=confidence,
            evidence_refs=evidence_refs,
            missing_evidence=tuple(ai_result.verdict.missing_evidence) if ai_result else (),
        )

        expires_at = datetime.now(UTC) + _EXPIRY
        options = DeterminationOptions(
            justification=justification,
            assessment_id=assessment.id,
            rationale=(
                f"{tier.value} evidence: {justification.value} (confidence {confidence.value})"
            ),
            expires_at=expires_at,
        )
        # Propagates DeterminationIdUnresolved / ViolationNotFound as-is —
        # not caught here, per this module's docstring.
        link_id = await iq.create_determination(finding_ref, options)

        _persist_rule_results(session, finding.id, engine_outcome)
        if ai_result is not None:
            _persist_ai_verdict(
                session,
                finding.id,
                model_id=model_id,
                prompt_version=prompt_version,
                ai_result=ai_result,
            )
        session.add(
            IqDeterminationLink(finding_id=finding.id, policy_waiver_id=link_id, expiry=expires_at)
        )
    else:
        _persist_rule_results(session, finding.id, engine_outcome)
        if ai_result is not None:
            _persist_ai_verdict(
                session,
                finding.id,
                model_id=model_id,
                prompt_version=prompt_version,
                ai_result=ai_result,
            )

    finding.outcome = outcome
    finding.justification = justification if outcome is FindingOutcome.NOT_AFFECTED else None
    finding.tier = tier if outcome is FindingOutcome.NOT_AFFECTED else None
    finding.confidence = confidence
    finding.decided_by = actor
    finding.decided_at = datetime.now(UTC)

    _persist_audit_entry(
        session,
        assessment=assessment,
        finding=finding,
        outcome=outcome,
        tier=finding.tier,
        justification=finding.justification,
        confidence=confidence,
        engine_outcome=engine_outcome,
        actor=actor,
    )

    await session.flush()
    return finding


__all__ = [
    "DeterminationError",
    "build_not_affected_determination",
    "determine",
]
