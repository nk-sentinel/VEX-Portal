"""Orchestrate the collectors into an ``EvidencePack``, and snapshot the
decision-relevant extract into the ``evidence`` table.

Fetches the report, the vulnerability details for each CVE the report's
policy violations name, the artifact, and (where mapped) the source repo;
builds the app-independent ``EvidencePack`` (``app/evidence/pack.py``); and
derives the per-CVE ``Tier3Signals`` the rule engine needs from Nexus IQ's
own vuln lookup.

**Snapshot, do not reference.** Nexus IQ's build-stage reports purge on a
short window, but a determination made from this evidence must be
defensible indefinitely. Everything a reviewer or an auditor would need to
reconstruct why a finding was decided the way it was is written into the
``evidence`` table here, as a value, never as a pointer back into IQ or
ELK — see ``app.repos.models.Evidence``'s own docstring.

**``rootCauses[].listOfPaths`` is filtered to ``.class`` entries.**
``IqHttpClient.vulnerability`` already does this (see its own docstring,
design finding 2) before ``VulnDetail.root_causes`` is ever handed back
across the adapter boundary — a bare jar filename handed to
``app.artifact.presence.contains_class`` produces a meaningless answer. This
module re-filters defensively at the layer this task's brief names as
responsible for it: collection must not blindly trust that the only caller
of ``iq.vulnerability()`` always remembers to filter, since a second adapter
implementation (or a future change to this one) could reintroduce the bug
silently.

**A per-CVE collector failure makes that finding inconclusive, never
clear.** When ``iq.vulnerability()`` fails for one (cve, purl) pair, this
module does not abort collection for the whole report — it records a
:class:`CollectionFailure` and leaves that CVE's implicated class list
empty. An empty ``class_paths`` is exactly what ``app/rules/tier1.py`` and
``app/rules/tier2.py`` already read as "no implicated class known" and
report ``UNANSWERABLE`` for — which forces the whole finding to
``NEEDS_REVIEW`` (``app/rules/engine.py``'s priority order, point 2). A
broken collector must never silently present as "the class is absent".

**A known gap: no evidence source for ``Tier3Signals.reachable_with_call_path``
exists anywhere in this system.** Nexus IQ's own reachable-with-call-path
signal (docs/design.md's "Hard blockers": "reachable with call-path
evidence") would need to come from the policy report's violation data, but
neither ``PolicyViolation`` nor ``VulnDetail`` (``app/adapters/protocols.py``)
carries any such field, and nothing in ``fakes/data/iq.json``'s policy report
shape has one either — confirmed by inspection, not assumed absent.
``Tier3Signals.reachable_with_call_path`` is ``bool | None`` (Task 5-8 fix
round 1 widened it, mirroring ``kev``), defaulting to ``None`` — this
module always leaves it unset (``None``, "never checked"), never passes a
guessed ``False``. See that field's own docstring in ``app/rules/engine.py``
for why ``None`` deliberately does NOT hard-block here the way an unknown
``kev`` does, and ``app/rules/registry.py``'s ``PENDING_EVIDENCE`` for this
gap documented alongside the three unregistered rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.errors import AdapterError
from app.adapters.protocols import (
    ArtifactStore,
    IqClient,
    Remediation,
    SourceControl,
    SourceRepository,
    SymbolHit,
    VulnDetail,
)
from app.artifact.errors import ArtifactTooLarge, MalformedArtifact
from app.evidence.pack import EvidencePack, build_pack
from app.repos.models import Evidence
from app.rules.engine import Tier3Signals


class CollectionError(Exception):
    """Evidence collection could not proceed at all: the report or the
    artifact could not be retrieved, or the artifact could not be parsed.

    Distinct from :class:`CollectionFailure`, which marks a single CVE's
    supporting IQ data as missing without aborting collection for every
    other finding in the same report.
    """


@dataclass(frozen=True, slots=True)
class CollectionFailure:
    """One piece of supporting evidence that could not be collected.

    ``cve``/``purl`` are empty strings for a failure that is not specific to
    one finding (e.g. the source-control mapping lookup). The finding this
    describes is never treated as clear or as affected on account of a
    collection failure — see this module's docstring.
    """

    cve: str
    purl: str
    reason: str


@dataclass(frozen=True, slots=True)
class CollectedEvidence:
    """Everything collection produced for one (application, report,
    artifact) triple: the app-independent evidence pack, the per-CVE
    Tier 3 signals the rule engine needs, and reviewer-context extras.
    """

    pack: EvidencePack

    #: CVE -> the intrinsic facts Nexus IQ's vuln lookup returned for it.
    vuln_details: dict[str, VulnDetail] = field(default_factory=dict)

    #: CVE -> the escalation signals built from vuln_details/remediation,
    #: ready to hand to ``RuleEngine.evaluate_component``.
    tier3_signals: dict[str, Tier3Signals] = field(default_factory=dict)

    source_control: SourceControl | None = None

    #: CVE -> source hits complementing the constant-pool reference scan
    #: (docs/design.md Tier 2 item 7). Reviewer context; no rule reads this.
    symbol_hits: dict[str, list[SymbolHit]] = field(default_factory=dict)

    failures: tuple[CollectionFailure, ...] = ()


def _class_paths_only(paths: list[str]) -> list[str]:
    """Defensive re-filter to ``.class`` entries — see this module's
    docstring for why this runs again even though the IQ adapter already
    filters."""
    return [path for path in paths if path.endswith(".class")]


def _symbol_from_class_path(class_path: str) -> str:
    """The simple (possibly nested) class name to search source for, e.g.
    ``org/apache/commons/text/StringSubstitutor.class`` -> ``StringSubstitutor``,
    ``com/example/Outer$Inner.class`` -> ``Inner``."""
    simple = class_path.rsplit("/", 1)[-1].removesuffix(".class")
    return simple.rsplit("$", 1)[-1]


def _repo_from_url(repository_url: str) -> str | None:
    """Bitbucket Data Center's ``{projectKey}/{repoSlug}`` convention
    (``app/adapters/bitbucket/client.py``) from a ``.../scm/{project}/{repo}.git``
    URL. Returns ``None`` for any URL that does not match this shape, rather
    than guessing — symbol search is skipped for that CVE, not fabricated
    from a wrong repo identifier.
    """
    marker = "/scm/"
    index = repository_url.find(marker)
    if index == -1:
        return None
    remainder = repository_url[index + len(marker) :].strip("/")
    parts = remainder.split("/")
    if len(parts) < 2:
        return None
    project_key, repo_slug = parts[0], parts[1]
    repo_slug = repo_slug.removesuffix(".git")
    if not project_key or not repo_slug:
        return None
    return f"{project_key.upper()}/{repo_slug}"


def build_tier3_signals(vuln: VulnDetail, remediation: Remediation | None) -> Tier3Signals:
    """The pure combination step: Nexus IQ's vuln lookup + remediation
    lookup into the ``Tier3Signals`` the rule engine needs.

    Extracted from :func:`collect_evidence`'s per-violation loop (which owns
    the network I/O and per-CVE failure handling) so this mapping is
    directly testable without a database session or adapter clients — in
    particular so the unknown-KEV-survives-the-whole-path property (Task 5-8
    fix round 1) has a narrow, dedicated test that would fail if a future
    edit reintroduced a coercion to a safe-looking default anywhere in this
    step.

    Every field is passed through unchanged from its source, never
    substituted with a guessed default:

    - ``kev`` comes straight from ``vuln.is_kev`` — already tri-state (see
      that field's own docstring): ``None`` means IQ's response carried no
      ``kevData`` at all, and that ``None`` must reach ``Tier3Signals.kev``
      exactly as-is, not become a coerced ``False``.
    - ``fix_available`` is ``None`` when ``remediation is None`` — either
      the lookup failed (the caller passes ``None`` in that case) or IQ has
      never scanned this component (a legitimate, distinct absence — see
      ``Remediation``'s own docstring); ``False`` only when IQ positively
      confirmed no fix via its documented empty-``versionChanges`` shape;
      ``True`` only when a fix version was found.
    - ``reachable_with_call_path`` is always ``None`` (the type's default) —
      see this module's docstring and ``Tier3Signals.reachable_with_call_path``'s
      own docstring for why nothing populates this today, and why ``None``
      is the only honest value here.
    """
    return Tier3Signals(
        kev=vuln.is_kev,
        epss=vuln.epss_score,
        cvss_base_score=vuln.cvss_score,
        cvss_vector=vuln.cvss_vector,
        fix_available=None if remediation is None else remediation.fix_version is not None,
    )


async def collect_evidence(
    application_id: str,
    report_id: str,
    artifact_coordinates: str,
    *,
    assessment_id: str,
    iq: IqClient,
    artifact_store: ArtifactStore,
    source_repository: SourceRepository,
    session: AsyncSession,
) -> CollectedEvidence:
    """Fetch every collector's evidence for one report/artifact and build
    the pack, snapshotting the decision-relevant extract into ``evidence``.

    Args:
        application_id: the Nexus IQ application id.
        report_id: the Nexus IQ report id.
        artifact_coordinates: the JFrog Artifactory coordinates (or image
            reference).
        assessment_id: the persisted ``Assessment`` row this evidence
            belongs to — must already exist (``evidence.assessment_id`` is a
            foreign key).
        iq: the Nexus IQ client.
        artifact_store: the JFrog Artifactory client.
        source_repository: the Bitbucket Data Center client.
        session: the database session evidence rows are added to. This
            function flushes but does not commit — the caller owns the
            transaction boundary.

    Raises:
        CollectionError: the report or artifact could not be retrieved, or
            the artifact could not be parsed. Per-CVE vuln-lookup failures
            do NOT raise this — see :class:`CollectionFailure`.
    """
    try:
        report = await iq.report(application_id, report_id)
    except AdapterError as exc:
        raise CollectionError(
            f"could not retrieve report {report_id!r} for application "
            f"{application_id!r}: {exc}"
        ) from exc

    try:
        artifact = await artifact_store.fetch(artifact_coordinates)
    except AdapterError as exc:
        raise CollectionError(
            f"could not retrieve artifact at {artifact_coordinates!r}: {exc}"
        ) from exc

    vuln_details: dict[str, VulnDetail] = {}
    tier3_signals: dict[str, Tier3Signals] = {}
    findings: dict[str, list[str]] = {}
    failures: list[CollectionFailure] = []

    for violation in report.violations:
        try:
            vuln = await iq.vulnerability(violation.cve, violation.purl)
        except AdapterError as exc:
            failures.append(
                CollectionFailure(cve=violation.cve, purl=violation.purl, reason=str(exc))
            )
            # No implicated class known for this CVE — the tier 1/2 rules
            # already read an empty class_paths as UNANSWERABLE, which
            # forces NEEDS_REVIEW rather than manufacturing a clear.
            findings.setdefault(violation.cve, [])
            continue

        vuln_details[violation.cve] = vuln
        findings[violation.cve] = _class_paths_only(vuln.root_causes)

        remediation: Remediation | None
        try:
            remediation = await iq.remediation(application_id, violation.purl)
        except AdapterError as exc:
            failures.append(
                CollectionFailure(
                    cve=violation.cve,
                    purl=violation.purl,
                    reason=f"remediation lookup failed: {exc}",
                )
            )
            remediation = None

        tier3_signals[violation.cve] = build_tier3_signals(vuln, remediation)

    try:
        pack = build_pack(
            artifact,
            report_component_sha1s={component.sha1 for component in report.components},
            findings=findings,
        )
    except (MalformedArtifact, ArtifactTooLarge) as exc:
        raise CollectionError(
            f"could not parse artifact at {artifact_coordinates!r}: {exc}"
        ) from exc

    source_control: SourceControl | None
    try:
        source_control = await iq.source_control(application_id)
    except AdapterError as exc:
        failures.append(
            CollectionFailure(cve="", purl="", reason=f"source control lookup failed: {exc}")
        )
        source_control = None

    symbol_hits: dict[str, list[SymbolHit]] = {}
    repo = _repo_from_url(source_control.repository_url) if source_control else None
    if repo is not None and source_control is not None:
        for cve, class_paths in findings.items():
            hits: list[SymbolHit] = []
            for class_path in class_paths:
                symbol = _symbol_from_class_path(class_path)
                try:
                    hits.extend(
                        await source_repository.search_symbol(
                            repo, symbol, source_control.base_branch
                        )
                    )
                except AdapterError as exc:
                    failures.append(
                        CollectionFailure(cve=cve, purl="", reason=f"symbol search failed: {exc}")
                    )
            if hits:
                symbol_hits[cve] = hits

    await _snapshot(
        session=session,
        assessment_id=assessment_id,
        report_id=report_id,
        artifact_coordinates=artifact_coordinates,
        pack=pack,
        vuln_details=vuln_details,
        symbol_hits=symbol_hits,
    )

    return CollectedEvidence(
        pack=pack,
        vuln_details=vuln_details,
        tier3_signals=tier3_signals,
        source_control=source_control,
        symbol_hits=symbol_hits,
        failures=tuple(failures),
    )


async def _snapshot(
    *,
    session: AsyncSession,
    assessment_id: str,
    report_id: str,
    artifact_coordinates: str,
    pack: EvidencePack,
    vuln_details: dict[str, VulnDetail],
    symbol_hits: dict[str, list[SymbolHit]],
) -> None:
    """Write the decision-relevant extract into ``evidence``. Values only —
    never a pointer back into IQ, Artifactory, Bitbucket, or ELK, all of
    which may not hold this data indefinitely."""
    session.add(
        Evidence(
            assessment_id=assessment_id,
            collector="artifact_inventory",
            key="inventory_summary",
            value_json=dict(pack.inventory_summary),
            source_ref=artifact_coordinates,
        )
    )
    session.add(
        Evidence(
            assessment_id=assessment_id,
            collector="provenance",
            key="fingerprint",
            value_json={
                "verdict": pack.provenance.verdict.value,
                "matched": pack.provenance.matched,
                "report_total": pack.provenance.report_total,
                "ratio": pack.provenance.ratio,
                "surplus_ratio": pack.provenance.surplus_ratio,
            },
            source_ref=report_id,
        )
    )
    for component in pack.components:
        session.add(
            Evidence(
                assessment_id=assessment_id,
                collector="evidence_pack",
                key=f"component:{component.cve}",
                value_json={
                    "class_paths": list(component.class_paths),
                    "class_present": component.class_present,
                    "referenced": component.referenced,
                    "reference_scan_conclusive": component.reference_scan_conclusive,
                },
                source_ref=report_id,
            )
        )
    for cve, vuln in vuln_details.items():
        value: dict[str, Any] = {
            "cvss_vector": vuln.cvss_vector,
            "cvss_score": vuln.cvss_score,
            "epss_score": vuln.epss_score,
            "is_kev": vuln.is_kev,
            "cwe_ids": list(vuln.cwe_ids),
            "affected_version_range": vuln.affected_version_range,
            "root_causes": list(vuln.root_causes),
        }
        session.add(
            Evidence(
                assessment_id=assessment_id,
                collector="iq_vulnerability",
                key=f"vulnerability:{cve}",
                value_json=value,
                source_ref=cve,
            )
        )
    for cve, hits in symbol_hits.items():
        session.add(
            Evidence(
                assessment_id=assessment_id,
                collector="bitbucket_symbol_search",
                key=f"symbol_search:{cve}",
                value_json={
                    "hits": [{"path": h.path, "line": h.line, "snippet": h.snippet} for h in hits]
                },
                source_ref=cve,
            )
        )
    await session.flush()
