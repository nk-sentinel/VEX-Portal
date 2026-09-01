"""The real Nexus IQ client — the one implementation, run here against
``fakes/iq`` and at work against the real IQ Server.

Vocabulary note: this module says "waiver" throughout. That is deliberate and
required, not an oversight — see docs/naming.md and
``app/adapters/protocols.py``'s module docstring. Nexus IQ's own REST API is
built on ``policyWaivers``; a client that renamed the vendor's own fields
internally would still have to speak the vendor's vocabulary at every request
and response boundary, so nothing is gained by pretending otherwise here. The
portal's own vocabulary — *determination* — is what this module hands back
across the ``IqClient`` Protocol boundary; nothing above this package ever
sees the word "waiver".

**Two design findings from building the fakes faithfully (Task 7) are
resolved here — see each method's docstring for the mechanics:**

1. IQ's waiver-creation endpoints return ``204 No Content`` with no id in the
   body, which is in tension with the already-committed
   ``IqClient.create_determination() -> str``. :meth:`IqHttpClient.create_determination`
   performs a follow-up ``applicableWaivers`` read to obtain the id, and
   raises rather than returning a placeholder if that read finds nothing —
   see its docstring.
2. ``rootCauses[].listOfPaths`` can contain a bare jar filename alongside the
   ``.class`` path. :meth:`IqHttpClient.vulnerability` filters to entries
   ending ``.class`` before they ever reach ``VulnDetail.root_causes``, so
   nothing downstream (in particular ``app.evidence.pack.build_pack``, which
   feeds ``root_causes`` to ``contains_class`` as though every entry were a
   class) has to remember to filter it itself.

**A third finding, found while implementing this client, not called out in
the Task 7 report:** ``create_determination`` is typed
``(finding: FindingRef, options: DeterminationOptions) -> str``, and
``FindingRef`` deliberately carries no ``report_id`` or ``policyViolationId``
(see its docstring — a violation id is scan-time context that goes stale on
every re-scan, which is exactly why it is not part of a finding's identity).
But IQ's waiver-creation endpoints require a *current* ``policyViolationId``
in the path, and nothing in ``FindingRef``/``DeterminationOptions`` supplies
one. Resolving this needed one more real, documented Sonatype endpoint —
``GET /api/v2/reports/applications/{applicationId}`` (Sonatype's "Report
REST API", confirmed at help.sonatype.com/en/report-rest-api.html) — to
discover the application's current report id without already knowing one,
then the existing ``.../policy`` endpoint to find the violation. This route
was not in the Task 7 brief's list and had no fake implementation; a minimal,
vendor-shaped version was added to ``fakes/iq/main.py`` under
``fakes/README.md``'s own standing policy ("If a real client needs a new
fake route to be testable, add the smallest possible canned response for
it"). Flagged in the Task 8 report for the plan owner's review — this is a
gap in the committed Protocol, not something this client can fix by changing
``FindingRef`` on its own authority.
"""

from __future__ import annotations

import re
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

import httpx

from app.adapters._transport import (
    DEFAULT_TIMEOUT,
    get_or_none,
    get_required,
    raise_for_status,
    send,
    send_or_none,
)
from app.adapters.errors import AdapterError
from app.adapters.protocols import (
    Application,
    DeterminationOptions,
    FindingRef,
    PolicyViolation,
    RawReport,
    Remediation,
    ReportComponent,
    SourceControl,
    VulnDetail,
)

#: The owner scope every waiver this portal creates uses. Nexus IQ also
#: supports "organization" and "repository_container" scopes, but this
#: portal's model is one application per assessment, so "application" is the
#: only scope ``create_determination``/``revoke_determination`` ever use.
_OWNER_TYPE = "application"

_PURL_MAVEN_RE = re.compile(
    r"^pkg:maven/(?P<group>[^/]+)/(?P<artifact>[^@]+)@(?P<version>[^?]+)(?:\?type=(?P<ext>[^&]+))?$"
)


class ViolationNotFound(AdapterError):
    """No currently-open policy violation matches the (application, CVE,
    purl) a determination was requested for — e.g. it was remediated between
    admission and determination."""


class DeterminationIdUnresolved(AdapterError):
    """A waiver was created (the POST returned 204, matching Nexus IQ's real
    behaviour) but the follow-up ``applicableWaivers`` read found no matching
    record, so no id can be returned.

    Raised rather than returning a placeholder or empty string: a
    determination whose suppression id cannot be established is not one this
    portal can later revoke or audit, and
    ``iq_determination_link.policy_waiver_id`` is non-nullable.
    """


class _BearerAuth(httpx.Auth):
    """Authenticate as the requesting user's own token rather than the
    service credential — see :meth:`IqHttpClient.applications_for_user`."""

    def __init__(self, token: str) -> None:
        self._token = token

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = f"Bearer {self._token}"
        yield request


def _cve_from_violation(violation: dict[str, Any]) -> str | None:
    """Walk a policy violation's ``constraintViolations[].reasons[]`` for the
    one reference IQ tags as the CVE — see ``fakes/iq/main.py``'s identical
    walk, which this mirrors because both read the same real vendor shape.
    """
    for constraint in violation.get("constraintViolations", []):
        for reason in constraint.get("reasons", []):
            reference = reason.get("reference", {})
            if reference.get("type") == "SECURITY_VULNERABILITY_REFID":
                value = reference.get("value")
                return str(value) if value is not None else None
    return None


def _component_identifier_from_purl(purl: str) -> dict[str, Any]:
    """Reverse a Maven purl into the ``componentIdentifier`` shape IQ's
    remediation endpoint expects in its request body.

    Only Maven purls are handled — the only ecosystem this portal's sample
    scenario (and, so far, its design) needs. A non-Maven purl raises rather
    than guessing a shape IQ was never asked to remediate.
    """
    match = _PURL_MAVEN_RE.match(purl)
    if not match:
        raise ValueError(f"unsupported purl for IQ remediation lookup: {purl!r}")
    return {
        "format": "maven",
        "coordinates": {
            "groupId": match["group"],
            "artifactId": match["artifact"],
            "version": match["version"],
            "extension": match["ext"] or "jar",
        },
    }


def _parse_is_kev(body: dict[str, Any]) -> bool | None:
    """Resolve the tri-state KEV fact from one vulnerability response body.

    Three distinct facts, not two: ``kevData`` absent (or present but
    missing ``isKev``) means KEV status was never established for this CVE
    -> ``None``. A present ``kevData.isKev`` is trusted verbatim, whether
    ``True`` or ``False``. Coercing the absent case to ``False`` (the
    previous behaviour, ``bool((body.get("kevData") or {}).get("isKev",
    False))``) silently asserted "not a known-exploited vulnerability",
    which nobody established — and erased the very ``None`` that
    ``VulnDetail.is_kev``/``Tier3Signals.kev`` exist to carry, making the
    downstream tri-state fix unreachable from this adapter onward. See
    ``VulnDetail.is_kev``'s own docstring.
    """
    kev_data = body.get("kevData")
    if kev_data is None or "isKev" not in kev_data:
        return None
    return bool(kev_data["isKev"])


def _format_iq_timestamp(value: datetime) -> str:
    """Render a UTC-aware datetime the way IQ's own timestamps are shaped
    (``2026-09-08T00:00:00.000+0000`` — see ``fakes/iq/main.py``)."""
    if value.tzinfo is None:
        raise ValueError("expires_at must be timezone-aware")
    utc = value.astimezone(UTC)
    return f"{utc.strftime('%Y-%m-%dT%H:%M:%S')}.{utc.microsecond // 1000:03d}+0000"


def _encode_link_id(owner_type: str, owner_id: str, policy_waiver_id: str) -> str:
    """Pack everything :meth:`IqHttpClient.revoke_determination` needs into
    the single opaque string ``create_determination`` returns.

    ``IqClient.create_determination``'s docstring (``app/adapters/protocols.py``)
    is explicit that this id "carries no meaning outside the adapter that
    produced it" — this is exactly the license that statement grants: the
    DELETE endpoint needs ``ownerType``/``ownerId`` as well as the waiver id,
    and neither is available to :meth:`revoke_determination` from
    ``link_id`` alone unless this method packs them in.
    """
    return f"{owner_type}|{owner_id}|{policy_waiver_id}"


def _decode_link_id(link_id: str) -> tuple[str, str, str]:
    parts = link_id.split("|", 2)
    if len(parts) != 3:
        raise ValueError(f"malformed IQ determination link id: {link_id!r}")
    owner_type, owner_id, waiver_id = parts
    return owner_type, owner_id, waiver_id


class IqHttpClient:
    """Everything the portal needs from Nexus IQ, over real HTTP.

    The same class runs against ``fakes/iq`` (``adapter_mode=fake``) and the
    real IQ Server (``adapter_mode=real``) — see ``app/adapters/factory.py``.
    Only the base URL and credentials differ; there is no separate fake
    client class to drift from this one.
    """

    def __init__(
        self,
        *,
        base_url: str,
        service_user: str,
        service_token: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            auth=httpx.BasicAuth(service_user, service_token),
            timeout=DEFAULT_TIMEOUT,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def applications_for_user(self, user_token: str) -> list[Application]:
        """List the applications ``user_token`` is entitled to see.

        Authenticated as the requesting user's own token, not the service
        credential — entitlement is inherited from IQ's own token-scoped
        application list rather than reimplemented (see
        ``app/adapters/protocols.py``'s ``Application`` docstring).
        """
        path = "/api/v2/applications"
        response = await get_required(self._client, path, auth=_BearerAuth(user_token))
        return [Application(id=a["id"], name=a["name"]) for a in response.json()["applications"]]

    async def report(self, application_id: str, report_id: str) -> RawReport:
        """Snapshot one scan report: components (for provenance hashing) and
        policy violations (for finding identity), from IQ's raw and policy
        report endpoints respectively.

        Both 404 as an error — the caller named this specific report id, and
        a report that has purged (IQ reports live on a short window) is
        something the caller needs to know about, not silently treat as "no
        report".

        ``commit_sha``/``branch`` are always ``None``: this fake's report
        body carries only ``components`` at the top level, and whether a real
        IQ report carries commit/branch at all is an open item
        (``docs/design.md``) never confirmed against a real server. Returning
        ``None`` here is honest about what this call actually saw, rather
        than inventing a value from a different source (e.g. JFrog build
        info, fetched separately) under a field that claims to describe the
        report itself.
        """
        raw_path = f"/api/v2/applications/{application_id}/reports/{report_id}/raw"
        policy_path = f"/api/v2/applications/{application_id}/reports/{report_id}/policy"
        raw = (await get_required(self._client, raw_path)).json()
        policy = (await get_required(self._client, policy_path)).json()

        components = [
            ReportComponent(purl=c["packageUrl"], sha1=c["hash"]) for c in raw["components"]
        ]
        violations: list[PolicyViolation] = []
        for component in policy["components"]:
            for violation in component["violations"]:
                cve = _cve_from_violation(violation)
                if cve is None:
                    # A violation IQ raised for a non-CVE reason (license,
                    # quality policy) carries no CVE reference — outside this
                    # portal's CVE-driven scope.
                    continue
                violations.append(
                    PolicyViolation(
                        cve=cve,
                        purl=component["packageUrl"],
                        policy_id=violation["policyId"],
                        violation_id=violation["policyViolationId"],
                        threat_level=violation.get("threatLevel"),
                    )
                )
        return RawReport(
            components=components,
            violations=violations,
            scan_id=report_id,
            commit_sha=None,
            branch=None,
        )

    async def vulnerability(self, vuln_id: str, component_purl: str | None) -> VulnDetail:
        """Fetch the intrinsic, app-independent facts about one CVE.

        404s as an error — the caller asked about a specific CVE id, and an
        unrecognised CVE id here almost always means a bug upstream, not a
        legitimate absence.

        ``root_causes`` is filtered to entries ending ``.class`` — see this
        module's docstring, design finding 2. ``rootCauses[].listOfPaths``
        can carry a bare jar filename alongside the class path; an unfiltered
        jar name reaching ``app.artifact.presence.contains_class`` (via
        ``app.evidence.pack.build_pack``) as though it were a class path
        produces a meaningless answer.

        ``is_kev`` is tri-state — see :func:`_parse_is_kev` and
        ``VulnDetail.is_kev``'s own docstring. An absent ``kevData`` block
        becomes ``None`` ("never established"), never a coerced ``False``.
        """
        path = f"/api/v2/vulnerabilities/{vuln_id}"
        params = {"componentIdentifier": component_purl} if component_purl else None
        body = (await get_required(self._client, path, params=params)).json()

        root_causes_raw = body.get("rootCauses", [])
        root_causes = [
            entry_path
            for cause in root_causes_raw
            for entry_path in cause.get("listOfPaths", [])
            if entry_path.endswith(".class")
        ]
        # Scoped to the first root-cause grouping's range rather than the
        # top-level vulnerableVersionRanges: VulnDetail.affected_version_range
        # is documented as the range "of the queried component", and
        # rootCauses is IQ's own per-implicated-class grouping.
        affected_version_range = (
            root_causes_raw[0].get("versionRange") if root_causes_raw else None
        )
        main_severity = body.get("mainSeverity") or {}
        return VulnDetail(
            cve=body["identifier"],
            cvss_vector=main_severity.get("vector"),
            cvss_score=main_severity.get("score"),
            epss_score=(body.get("epssData") or {}).get("currentScore"),
            is_kev=_parse_is_kev(body),
            cwe_ids=[cwe["id"] for cwe in (body.get("weakness") or {}).get("cweIds", [])],
            affected_version_range=affected_version_range,
            root_causes=root_causes,
        )

    async def remediation(self, application_id: str, purl: str) -> Remediation | None:
        """Look up whether a fix exists for ``purl``.

        404s as an absence (a component IQ has never scanned): the fake
        never actually returns one for this endpoint (IQ represents "no fix"
        as an empty ``versionChanges`` array on a 200, which is handled
        below), but a real, wholly unrecognised application/component pair
        could plausibly 404, and that would be a legitimate absence rather
        than an error.
        """
        path = f"/api/v2/components/remediation/application/{application_id}"
        body_json = {"componentIdentifier": _component_identifier_from_purl(purl)}
        response = await send_or_none(self._client, "POST", path, json=body_json)
        if response is None:
            return None
        changes = response.json().get("remediation", {}).get("versionChanges", [])
        if not changes:
            # Sonatype's own documented "nothing to recommend" shape — never
            # a fix_version of None distinguished from "unknown"; see
            # Remediation's docstring and CLAUDE.md rule 5.
            return Remediation(fix_version=None, is_transitive=False)
        first = changes[0]
        coordinates = first.get("data", {}).get("component", {}).get("componentIdentifier", {}).get(
            "coordinates", {}
        )
        return Remediation(
            fix_version=coordinates.get("version"),
            is_transitive=not first.get("directDependency", True),
        )

    async def source_control(self, application_id: str) -> SourceControl | None:
        """Read where an application's source lives.

        404s as an absence: no source-control entry has been mapped for this
        application yet — a legitimate, common state (see
        ``app/adapters/protocols.py``'s ``SourceControl`` docstring: "read
        (and, on first use, created)").
        """
        path = f"/api/v2/sourceControl/application/{application_id}"
        response = await get_or_none(self._client, path)
        if response is None:
            return None
        body = response.json()
        return SourceControl(repository_url=body["repositoryUrl"], base_branch=body["baseBranch"])

    async def create_determination(
        self, finding: FindingRef, options: DeterminationOptions
    ) -> str:
        """Record a ``NOT_AFFECTED`` determination against ``finding`` as a
        Nexus IQ policy waiver, and return the id of the waiver it created.

        **The returned id comes from a follow-up query, not from the create
        call itself.** Nexus IQ's real waiver-creation endpoints answer
        ``204 No Content`` with no id in the body (confirmed against
        Sonatype's own docs — see this module's docstring, design finding 1).
        This method: POSTs the waiver, observes the 204, then reads back
        ``GET .../applicableWaivers`` for the violation it just waived and
        matches on the ``comment`` it set, to identify which of (possibly
        several) waivers on that violation is the one just created. If that
        follow-up read finds no match, this raises
        :class:`DeterminationIdUnresolved` rather than returning a
        placeholder or empty string — a determination whose suppression id
        cannot be established is not one this portal can later revoke or
        audit.

        **Resolving the violation id.** ``finding`` deliberately carries no
        ``policyViolationId`` (violation ids are reassigned on every re-scan;
        see ``FindingRef``'s docstring), so this method first has to find the
        *current* one for ``(finding.cve, finding.purl)``. It does this by
        listing the application's reports (``GET
        /api/v2/reports/applications/{id}`` — a real, documented Sonatype
        endpoint not otherwise used by this client; see this module's
        docstring, design finding 3), taking the most recently evaluated one,
        and searching its policy view for a violation matching both the CVE
        and the component. If none is found — e.g. the finding was
        remediated between admission and this call — this raises
        :class:`ViolationNotFound`.
        """
        report_id = await self._current_report_id(finding.application_id)
        violation_id = await self._find_violation_id(
            finding.application_id, report_id, finding.cve, finding.purl
        )

        waiver_reason_id = await self._not_exploitable_waiver_reason_id()
        comment = f"determination {options.assessment_id}: {options.rationale}"
        create_path = f"/api/v2/policyWaivers/{_OWNER_TYPE}/{finding.application_id}/{violation_id}"
        create_response = await send(
            self._client,
            "POST",
            create_path,
            json={
                "comment": comment,
                "waiverReasonId": waiver_reason_id,
                "expiryTime": _format_iq_timestamp(options.expires_at),
                "matcherStrategy": "EXACT_COMPONENT",
                # A fix becoming available ends the basis for "not affected"
                # (CLAUDE.md rule 5: no-fix-available is a different outcome
                # entirely) — so the waiver should stop applying the moment
                # one exists, independent of the portal's own 7-day expiry.
                "expireWhenRemediationAvailable": True,
            },
        )
        raise_for_status("POST", create_path, create_response)

        applicable_path = f"/api/v2/policyViolations/{violation_id}/applicableWaivers"
        applicable_response = await get_required(self._client, applicable_path)
        active = applicable_response.json().get("activeWaivers", [])
        matches = [w for w in active if w.get("comment") == comment]
        if not matches:
            raise DeterminationIdUnresolved(
                f"created a waiver for violation {violation_id} but the follow-up "
                "applicableWaivers read found no matching record"
            )
        policy_waiver_id: str = matches[-1]["policyWaiverId"]
        return _encode_link_id(_OWNER_TYPE, finding.application_id, policy_waiver_id)

    async def revoke_determination(self, link_id: str) -> None:
        """Delete the waiver ``link_id`` (as returned by
        :meth:`create_determination`) identifies.

        A 404 here is treated as success, not an error: DELETE is naturally
        idempotent, and 404 means the waiver is already gone — exactly the
        postcondition a revoke wants, whether that happened via this call
        previously, via the waiver's own expiry, or via a change made
        directly in IQ.
        """
        owner_type, owner_id, waiver_id = _decode_link_id(link_id)
        path = f"/api/v2/policyWaivers/{owner_type}/{owner_id}/{waiver_id}"
        response = await send(self._client, "DELETE", path)
        if response.status_code == 404:
            return
        raise_for_status("DELETE", path, response)

    async def _current_report_id(self, application_id: str) -> str:
        path = f"/api/v2/reports/applications/{application_id}"
        response = await get_required(self._client, path)
        reports = response.json()
        if not reports:
            raise ViolationNotFound(f"no reports found for application {application_id}")
        latest = max(reports, key=lambda r: r["evaluationDate"])
        # Sonatype's documented shape carries the report id only embedded in
        # a URL (reportDataUrl / reportHtmlUrl), not as its own field — see
        # this module's docstring, design finding 3.
        return str(latest["reportDataUrl"]).rsplit("/", 1)[-1]

    async def _find_violation_id(
        self, application_id: str, report_id: str, cve: str, purl: str
    ) -> str:
        policy_path = f"/api/v2/applications/{application_id}/reports/{report_id}/policy"
        policy = (await get_required(self._client, policy_path)).json()
        for component in policy["components"]:
            if component["packageUrl"] != purl:
                continue
            for violation in component["violations"]:
                if _cve_from_violation(violation) == cve:
                    violation_id: str = violation["policyViolationId"]
                    return violation_id
        raise ViolationNotFound(
            f"no open policy violation for {cve} against {purl} in application {application_id}"
        )

    async def _not_exploitable_waiver_reason_id(self) -> str | None:
        """Best-effort map from a portal determination to one of IQ's
        (site-configurable, free-text) waiver reasons.

        IQ's waiver reasons are an admin-defined catalogue of human-readable
        strings with generated ids — there is no stable, vendor-defined id
        for "code not present" the way there is for, say, an HTTP status
        code. Every justification ``create_determination`` is ever called
        with is one ``Justification.justifies_determination()`` accepts
        (``Determination.validate`` enforces this before a determination is
        ever committed), and all five read as "not exploitable" to an IQ
        reviewer, so that text is used uniformly rather than inventing a
        finer-grained mapping IQ's own reason catalogue has no room to
        express. Falls back to "Other", then to the first configured reason,
        so a create call never fails purely because the site's reason
        catalogue lacks an exact match.
        """
        response = await get_required(self._client, "/api/v2/waiverReasons")
        reasons = response.json().get("waiverReasons", [])
        if not reasons:
            return None
        by_text = {r["reasonText"].strip().lower(): r["id"] for r in reasons}
        for candidate in ("not exploitable", "other"):
            if candidate in by_text:
                return str(by_text[candidate])
        return str(reasons[0]["id"])
