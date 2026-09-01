"""The AI adjudicator, wrapped with the safety machinery docs/design.md's
"AI adjudication" section requires: strict output validation, mandatory
abstention, an independent refute pass on every proposed clear, and a
CVE-intrinsic cache consulted before the (expensive) per-finding call.

**Evidence pack in, strict closed output out.** ``app.adapters.llm.client``
already builds the adjudicator's prompt from a fixed evidence pack and forces
a closed-enum tool call — this module never touches prompt text. Its job is
everything docs/design.md asks for *around* that call:

1. **The CVE-intrinsic cache is consulted first.** What a CVE's CVSS/EPSS/
   KEV/root-causes are is app-independent; only whether it applies to a
   given application is per-app. ``cve_profile`` caches exactly the
   app-independent part — Nexus IQ's own vuln lookup for the CVE — so a
   popular CVE seen across many applications is looked up once, not once
   per assessment. See "Why this caches VulnDetail, not an AiVerdictDto"
   below for why this is scoped this way rather than caching the
   adjudicator's own applicability verdict.

2. **Output is validated against the domain contract, not just the DTO's
   types.** ``AiVerdictDto``'s fields are already enum-typed by the adapter,
   but nothing there stops a model from proposing ``not_affected`` with no
   justification, or with a Tier-3-only justification
   (``protected_at_perimeter``/``protected_by_mitigating_control``) that
   ``Justification.justifies_determination()`` forbids. :func:`adjudicate_finding`
   rejects both — the same invariant ``Determination.validate`` enforces
   later, checked here too so a malformed verdict is a failure, never
   silently coerced into something that would slip past that later gate on
   a technicality (e.g. by construction from a differently-shaped caller).

3. **Abstention is first-class.** ``Confidence.INSUFFICIENT`` (or
   ``Confidence.LOW``, per ``Confidence.abstains()``) routes to human review
   with no refute pass — there is nothing to refute. So does a proposed
   ``State.UNDER_INVESTIGATION`` verdict, regardless of confidence: that
   state *is* "awaiting human review" (docs/design.md's terminology table).

4. **A refute pass runs on every proposed clear.** A second, independent
   call to the same evidence-bound ``adjudicate()`` — not a shared
   conversation, a fresh forced-tool-call invocation — is asked to
   adjudicate the identical evidence again. Agreement (also
   ``NOT_AFFECTED``, non-abstaining) confirms the clear; anything else is
   disagreement and routes to review. **Auto-reject (``State.AFFECTED``,
   non-abstaining) needs no refute pass** — it is already the safe
   direction: nothing is suppressed, the IQ violation stays open regardless
   of whether the reject was itself correct.

**Why this caches ``VulnDetail``, not an ``AiVerdictDto``.** The obvious
reading of "cache what the adjudicator produces, keyed by CVE" would cache
:class:`~app.adapters.protocols.AiVerdictDto` — but that DTO's ``state`` IS
the per-app applicability answer, and its ``evidence_refs`` are built from
the pack's own app-specific facts (``class_present``, ``referenced``,
provenance). Caching it across applications would silently reuse one app's
"not affected" for a different app that may reach the vulnerable code
differently — exactly what "only applicability is per-app" (docs/design.md)
forbids. ``Adjudicator.adjudicate(pack, finding)`` (the Protocol already
committed in an earlier task) has no way to ask for CVE-only, app-independent
reasoning separately from applicability — splitting that would mean adding a
new Adjudicator Protocol method, which is outside this task's file scope
(``app/services/adjudication.py`` only) and would ripple into the adapter and
fakes both already tested. ``VulnDetail`` (Nexus IQ's own CVE-intrinsic vuln
lookup: CVSS/EPSS/KEV/CWE/root-causes) is the one thing reachable from this
service that is genuinely CVE-only and has an unambiguous data source
(``IqClient.vulnerability``), so this is what ``cve_profile`` holds here.
Flagged explicitly in the Task 5-8 report as a scoping decision, not a
silent reinterpretation of the brief.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.protocols import Adjudicator, AiVerdictDto, FindingRef, IqClient, VulnDetail
from app.domain.determination import State
from app.evidence.pack import EvidencePack
from app.repos.models import CveProfile


class AdjudicationError(Exception):
    """Base for a failure raised while adjudicating one finding."""


class MalformedVerdict(AdjudicationError):
    """The adjudicator's response does not satisfy the domain contract a
    ``NOT_AFFECTED`` verdict must meet: a justification
    ``Justification.justifies_determination()`` permits, and at least one
    evidence reference. A malformed response is a failure, not a guess —
    never silently coerced into something ``Determination.validate`` would
    later accept on a technicality.
    """


@dataclass(frozen=True, slots=True)
class AdjudicationResult:
    """The outcome of adjudicating one finding, including the refute pass
    when one ran.
    """

    #: The adjudicator's primary verdict for this finding.
    verdict: AiVerdictDto

    #: True when this finding must route to a human: the primary verdict
    #: abstained (or proposed UNDER_INVESTIGATION), or a refute pass on a
    #: proposed clear disagreed. False for a confirmed clear or a reject —
    #: both are outcomes the determination service (Task 8) may act on
    #: without further human involvement.
    requires_review: bool

    #: The CVE-intrinsic facts consulted before adjudicating — see this
    #: module's docstring on the CVE-intrinsic cache.
    vuln_detail: VulnDetail

    #: Set only when a refute pass ran (i.e. the primary verdict proposed
    #: NOT_AFFECTED and did not abstain).
    refute_verdict: AiVerdictDto | None = None


def _validate_verdict(verdict: AiVerdictDto) -> None:
    """Reject a ``NOT_AFFECTED`` verdict that does not satisfy the domain
    contract. A no-op for every other state — those carry no such
    invariant."""
    if verdict.state is not State.NOT_AFFECTED:
        return
    if verdict.justification is None:
        raise MalformedVerdict("adjudicator proposed not_affected with no justification")
    if not verdict.justification.justifies_determination():
        raise MalformedVerdict(
            f"adjudicator proposed not_affected using justification "
            f"{verdict.justification.value!r}, which may not justify a not_affected "
            "determination (Tier 3 evidence may never clear a finding)"
        )
    if not verdict.evidence_refs:
        raise MalformedVerdict("adjudicator proposed not_affected with no evidence references")


def _vuln_detail_to_json(vuln: VulnDetail) -> dict[str, Any]:
    return {
        "cve": vuln.cve,
        "cvss_vector": vuln.cvss_vector,
        "cvss_score": vuln.cvss_score,
        "epss_score": vuln.epss_score,
        "is_kev": vuln.is_kev,
        "cwe_ids": list(vuln.cwe_ids),
        "affected_version_range": vuln.affected_version_range,
        "root_causes": list(vuln.root_causes),
    }


def _vuln_detail_from_json(data: dict[str, Any]) -> VulnDetail:
    return VulnDetail(
        cve=data["cve"],
        cvss_vector=data["cvss_vector"],
        cvss_score=data["cvss_score"],
        epss_score=data["epss_score"],
        is_kev=data["is_kev"],
        cwe_ids=list(data["cwe_ids"]),
        affected_version_range=data["affected_version_range"],
        root_causes=list(data["root_causes"]),
    )


async def _get_or_fetch_vuln_detail(
    cve: str, purl: str | None, *, iq: IqClient, session: AsyncSession
) -> VulnDetail:
    """The CVE-intrinsic cache: read ``cve_profile`` first, and only call
    ``IqClient.vulnerability`` — the expensive, network-bound call — on a
    miss, then persist the result for the next caller asking about the same
    CVE, from any application.
    """
    cached = await session.get(CveProfile, cve)
    if cached is not None:
        return _vuln_detail_from_json(cached.intrinsic_json)

    vuln = await iq.vulnerability(cve, purl)
    session.add(CveProfile(cve=cve, intrinsic_json=_vuln_detail_to_json(vuln)))
    await session.flush()
    return vuln


async def adjudicate_finding(
    pack: EvidencePack,
    finding: FindingRef,
    *,
    adjudicator: Adjudicator,
    iq: IqClient,
    session: AsyncSession,
) -> AdjudicationResult:
    """Adjudicate one finding: consult the CVE-intrinsic cache, call the
    adjudicator, validate its output, and run the mandatory refute pass on
    any proposed clear.

    Args:
        pack: the fixed, app-specific evidence pack — the adjudicator's
            entire input beyond the finding identity itself.
        finding: which (application, CVE, component) case this is.
        adjudicator: the AI adjudicator.
        iq: the Nexus IQ client, used only for the CVE-intrinsic cache.
        session: the database session the cache reads/writes through. This
            function flushes but does not commit — the caller owns the
            transaction boundary.

    Raises:
        MalformedVerdict: the adjudicator's primary or refute verdict
            proposed ``NOT_AFFECTED`` without a valid justification or any
            evidence reference.
    """
    vuln_detail = await _get_or_fetch_vuln_detail(finding.cve, finding.purl, iq=iq, session=session)

    verdict = await adjudicator.adjudicate(pack, finding)
    _validate_verdict(verdict)

    if verdict.confidence.abstains() or verdict.state is State.UNDER_INVESTIGATION:
        # Nothing to refute — this already routes to a human.
        return AdjudicationResult(verdict=verdict, requires_review=True, vuln_detail=vuln_detail)

    if verdict.state is State.NOT_AFFECTED:
        refute_verdict = await adjudicator.adjudicate(pack, finding)
        _validate_verdict(refute_verdict)
        agrees = (
            refute_verdict.state is State.NOT_AFFECTED and not refute_verdict.confidence.abstains()
        )
        return AdjudicationResult(
            verdict=verdict,
            requires_review=not agrees,
            refute_verdict=refute_verdict,
            vuln_detail=vuln_detail,
        )

    # verdict.state is AFFECTED, non-abstaining: already the safe direction,
    # per this module's docstring — no refute pass needed.
    return AdjudicationResult(verdict=verdict, requires_review=False, vuln_detail=vuln_detail)
