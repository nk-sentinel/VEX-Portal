"""The boundary between the portal and the four systems it cannot reach directly.

Every external system — Nexus IQ, JFrog Artifactory, Bitbucket Data Center,
Bedrock, and ELK — is reached through one of the Protocols below. Nothing else
in the portal is allowed to import ``httpx`` or know a URL; these five
Protocols, and the data types they exchange, are the entire boundary. Real
clients (``app/adapters/{iq,jfrog,bitbucket,llm,elk}/client.py``) and fake
servers speak vendor formats on the outside and hand back these types on the
inside — the rest of the application, including the rule engine and the
adjudicator's caller, never sees a vendor response shape.

**Written from the portal's needs, not from each vendor's API surface.** A
Protocol method reads "give me the vulnerability details for this CVE against
this component", never "GET /api/v2/vulnerabilities/{id} with a
componentIdentifier query parameter". If ``IqClient`` mirrored Nexus IQ's REST
surface, a Sonatype API change would ripple through the whole codebase; because
it expresses the portal's needs instead, a vendor change is contained in one
client implementation.

**Vocabulary.** This module follows the project's naming rule (docs/naming.md)
for Nexus IQ's own term for the mechanism behind a Not Affected determination:
that term does not appear anywhere here, including in comments — the one
permitted exception is inside ``app/adapters/iq/``, where the vendor's own
vocabulary is unavoidable. ``IqClient.create_determination`` returns that
mechanism's id as a plain ``str``; the adapter translates IQ's vocabulary into
the portal's at the boundary, which is exactly what a boundary is for.

Every Protocol is ``@runtime_checkable`` so a fake implementation and a real
implementation can each be checked with ``isinstance`` against the same
contract — drift between the two is caught wherever that check runs, not
after the real client only fails once it reaches the work network.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from app.domain.determination import Confidence, Justification, State
from app.evidence.pack import EvidencePack

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Application:
    """One application the requesting user may raise an assessment against.

    Entitlement is inherited from Nexus IQ's user-token-scoped application
    list rather than reimplemented (see docs/design.md, RBAC) — this is
    exactly why ``IqClient.applications_for_user`` takes the user's own token
    rather than a service credential.
    """

    id: str
    name: str


@dataclass(frozen=True, slots=True)
class ReportComponent:
    """One component a scan identified, with the hash provenance compares.

    ``sha1`` is what :func:`app.evidence.pack.build_pack` matches against the
    artifact's own bundled libraries (``report_component_sha1s``) — the
    primary provenance check needs nothing beyond this.
    """

    purl: str
    sha1: str


@dataclass(frozen=True, slots=True)
class PolicyViolation:
    """One policy violation against one (CVE, component) case, as scanned.

    ``violation_id`` is deliberately never a case's identity elsewhere in the
    portal — Nexus IQ reassigns it on every re-scan. It is carried here only
    because it is scan-time context a caller may want to snapshot, mirroring
    ``violation_id_snapshot`` on the persisted ``Finding`` row.
    """

    cve: str
    purl: str
    policy_id: str
    violation_id: str
    threat_level: int | None


@dataclass(frozen=True, slots=True)
class RawReport:
    """A snapshotted scan report: what shipped, what violated policy, and how
    the scan identifies its own commit.

    Reports purge on a short window in Nexus IQ, so everything an assessment
    might need from one is captured here at admission time rather than kept
    as a pointer back into a system that will not hold it indefinitely.
    """

    components: list[ReportComponent]
    violations: list[PolicyViolation]
    scan_id: str | None
    commit_sha: str | None
    branch: str | None


@dataclass(frozen=True, slots=True)
class VulnDetail:
    """The intrinsic, app-independent facts about one CVE the tier rules read.

    App-independent on purpose: none of these vary by which application is
    being reviewed, which is what makes the CVE-intrinsic cache in
    docs/design.md ("computed once, cached org-wide, reused") sound.
    """

    cve: str
    cvss_vector: str | None
    cvss_score: float | None
    epss_score: float | None

    #: ``bool | None``, not a plain ``bool`` — tri-state, matching
    #: ``app.rules.engine.Tier3Signals.kev``. ``None`` means IQ's response
    #: carried no ``kevData`` block at all (KEV status was never
    #: established for this CVE), distinct from a confirmed ``False``
    #: (IQ positively reported this CVE is not on the KEV list). The IQ
    #: adapter (``app/adapters/iq/client.py``) is responsible for keeping
    #: these three facts distinct all the way from the HTTP response body:
    #: coercing an absent ``kevData`` block to ``False`` would silently
    #: assert "not a known-exploited vulnerability", which nobody
    #: established, and would re-enable automatic clearing for exactly the
    #: vulnerabilities most likely to be exploited — the same hazard
    #: ``Tier3Signals.kev``'s tri-state fix exists to prevent, reopened one
    #: layer up if this field is ever allowed to erase the unknown state
    #: before it reaches the engine.
    is_kev: bool | None

    cwe_ids: list[str]

    #: The version range of the queried component in which this CVE applies.
    #: ``None`` when the vendor has not scoped an affected range for it.
    affected_version_range: str | None

    #: The implicated class paths — Nexus IQ returns these as
    #: ``rootCauses[].listOfPaths``. This is what Tier 1's class-presence
    #: check consumes (see app.evidence.pack.ComponentEvidence.class_paths,
    #: which carries the identical concept once resolved against one CVE).
    root_causes: list[str]


@dataclass(frozen=True, slots=True)
class Remediation:
    """Whether — and how — a finding can be fixed.

    ``fix_version is None`` means no path forward exists. Per CLAUDE.md rule
    5 that is never a Not Affected determination: the portal marks the case
    ``RISK_ACCEPTANCE_REQUIRED`` and leaves the vendor-side violation open.
    """

    fix_version: str | None
    is_transitive: bool


@dataclass(frozen=True, slots=True)
class SourceControl:
    """Where an application's source lives, for Bitbucket symbol search.

    This is how the portal learns which repository an IQ application maps
    to — read (and, on first use, created) via Nexus IQ's own
    application-to-source-control mapping.
    """

    repository_url: str
    base_branch: str


@dataclass(frozen=True, slots=True)
class FindingRef:
    """Identifies one (application, CVE, component) case.

    Never a vendor violation id — those are reassigned on every re-scan, so a
    case that used one as its identity would fragment across scans. This
    mirrors the identity the persisted ``Finding`` row itself uses
    (``assessment_id``, ``cve``, ``purl``), substituting ``application_id``
    because assessment ids are portal-internal and adapters only ever see the
    application side of that relationship.
    """

    application_id: str
    cve: str
    purl: str


@dataclass(frozen=True, slots=True)
class DeterminationOptions:
    """What the portal needs recorded when a Not Affected determination commits.

    Everything vendor-specific about turning this into an enforcement
    record — reason-code lookups, comment formatting — is the IQ client's
    job; this is only the decision itself. ``expires_at`` is required, not
    optional: determinations expire at 7 days and are never auto-renewed
    (CLAUDE.md rule 4), and the vendor-side record must carry the same expiry
    the portal tracks rather than relying on the portal alone to remember it.
    """

    justification: Justification
    #: The portal's own assessment id, so the vendor-side record can be
    #: traced back to the case that produced it.
    assessment_id: str
    #: A one-line, human-readable rationale for the vendor-side record. Full
    #: rationale — evidence references, tier, confidence — stays in the
    #: portal's own audit trail, never round-tripped through the vendor.
    rationale: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class BuildInfo:
    """Supporting provenance evidence published by the build itself.

    Authoritative where published (see docs/design.md, Provenance) — stronger
    than artifact properties, weaker than the primary dependency-set
    fingerprint match that :func:`app.evidence.pack.build_pack` performs.
    Any field may be absent: not every build publishes this.
    """

    repository_url: str | None
    commit_sha: str | None
    branch: str | None


@dataclass(frozen=True, slots=True)
class SymbolHit:
    """One place a symbol was found in source, for the Tier 2 companion check
    to constant-pool analysis (docs/design.md, Tier 2 rule #7) — each catches
    reference patterns the other misses.
    """

    path: str
    line: int
    snippet: str


@dataclass(frozen=True, slots=True)
class AiVerdictDto:
    """The adjudicator's closed-enum output for one finding.

    Mirrors docs/design.md's strict output contract exactly: state,
    justification, confidence, evidence references, and missing evidence.
    ``confidence`` MUST be able to carry ``Confidence.INSUFFICIENT`` — that is
    the abstention path. Without it the "unsure" bucket stays silently empty
    and every ambiguous case gets forced into a confident-looking verdict
    (CLAUDE.md rule 3).
    """

    state: State
    justification: Justification | None
    confidence: Confidence
    evidence_refs: list[str]
    missing_evidence: list[str]


@dataclass(frozen=True, slots=True)
class ScanRecord:
    """The decision-relevant extract of one scan's SBOM and vulnerability data.

    ELK is the system of record for this; the portal references it rather
    than copying it, but snapshots exactly this extract, because an audit
    trail that depends on another team's retention policy is not a trail
    (docs/design.md, External systems).
    """

    scan_id: str
    components: list[ReportComponent]
    #: CVE ids ELK associates with this scan's components — enough to
    #: cross-reference against Nexus IQ's own report for the same build.
    cve_ids: list[str]


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class IqClient(Protocol):
    """Everything the portal needs from Nexus IQ.

    Application listing is scoped to the requesting user's own token, not a
    service credential — see :class:`Application`. ``create_determination``
    is the one method whose return value is a Nexus IQ id; the id itself
    carries no meaning outside the adapter that produced it, so it is passed
    back opaquely as a plain ``str`` to whichever caller later needs to
    revoke it.
    """

    async def applications_for_user(self, user_token: str) -> list[Application]: ...

    async def report(self, application_id: str, report_id: str) -> RawReport: ...

    async def vulnerability(self, vuln_id: str, component_purl: str | None) -> VulnDetail: ...

    async def remediation(self, application_id: str, purl: str) -> Remediation | None: ...

    async def source_control(self, application_id: str) -> SourceControl | None: ...

    async def create_determination(
        self, finding: FindingRef, options: DeterminationOptions
    ) -> str:
        """Record a Not Affected determination against ``finding``.

        Returns the id the vendor's enforcement mechanism assigns to the
        record it creates — the same string a later call to
        :meth:`revoke_determination` must pass back as ``link_id``.
        """
        ...

    async def revoke_determination(self, link_id: str) -> None: ...


@runtime_checkable
class ArtifactStore(Protocol):
    """Everything the portal needs from JFrog Artifactory.

    ``coordinates`` is deliberately opaque to everything outside the adapter:
    for a JAR/WAR this is an Artifactory path, for a containerised
    application it is an image reference — the caller does not need to know
    which.
    """

    async def fetch(self, coordinates: str) -> bytes: ...

    async def build_info(self, coordinates: str) -> BuildInfo | None: ...


@runtime_checkable
class SourceRepository(Protocol):
    """Everything the portal needs from Bitbucket Data Center."""

    async def search_symbol(self, repo: str, symbol: str, ref: str) -> list[SymbolHit]: ...

    async def file(self, repo: str, path: str, ref: str) -> bytes | None: ...


@runtime_checkable
class Adjudicator(Protocol):
    """The AI adjudicator, taking a fixed evidence pack and returning a closed
    verdict — never a free-form question (docs/design.md, AI adjudication).
    """

    async def adjudicate(self, pack: EvidencePack, finding: FindingRef) -> AiVerdictDto: ...


@runtime_checkable
class ScanArchive(Protocol):
    """Everything the portal needs from ELK.

    Referenced, not copied — see :class:`ScanRecord` for why the extract this
    returns is still snapshotted by the caller rather than re-read from ELK
    on demand.
    """

    async def sbom_for_scan(self, scan_id: str) -> ScanRecord | None: ...
