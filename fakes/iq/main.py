"""Fake Nexus IQ Lifecycle server.

THROWAWAY — see /fakes/README.md at the repo root before touching this file.

Serves the routes app.adapters.iq.client (Task 8) needs, shaped like the real
Sonatype IQ Server v2 REST API: applications, one report (raw + policy),
per-CVE vulnerability detail (kevData/epssData/mainSeverity/rootCauses),
component remediation, source-control mapping, and policy waivers
(create/list/delete) plus waiverReasons.

Vocabulary note: this file says "waiver" throughout, unlike the rest of the
portal. That is deliberate and required, not an oversight — see
docs/naming.md and app/adapters/protocols.py's module docstring. Nexus IQ's
own API uses ``policyWaivers`` and ``waiverReasonId``; a fake that renamed
the vendor's own fields would stop being a faithful stand-in for the vendor.

Response shapes below were verified against Sonatype's own published REST
API documentation (help.sonatype.com) as of this writing, with two
exceptions flagged inline where I could not find a documented example:
the raw/policy report's top-level fields beyond ``components`` (whether IQ
even carries commit/branch on a report is called out as an open question in
docs/design.md itself), and the POST .../sourceControl response body. See
fakes/README.md and the Task 7 report for the full list.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Response

from fakes._shared import load_json

app = FastAPI(title="fake-nexus-iq")

_DATA = load_json("iq.json")

# In-memory waiver store, keyed by policyWaiverId. Seeded empty — every
# waiver in here was created via POST during this process's lifetime. Lost
# on restart, same as every other piece of state in these fakes.
_waivers: dict[str, dict[str, Any]] = {}
# violationId -> policyWaiverId, so DELETE and applicableWaivers can find a
# waiver without the caller having to remember which owner it was filed
# under.
_waivers_by_violation: dict[str, list[str]] = {}

_VIOLATION_INDEX: dict[str, dict[str, Any]] = {}
for _report in _DATA["reports"].values():
    for _rid_reports in _report.values():
        for _component in _rid_reports["policy"]["components"]:
            for _violation in _component["violations"]:
                _VIOLATION_INDEX[_violation["policyViolationId"]] = {
                    **_violation,
                    "componentIdentifier": _component["componentIdentifier"],
                    "packageUrl": _component["packageUrl"],
                    "hash": _component["hash"],
                }


def _purl_from_component_identifier(component_identifier: dict[str, Any] | None) -> str | None:
    """Build a packageUrl the same shape IQ itself reports, from a client's
    componentIdentifier — the remediation endpoint's real request body only
    carries the latter (see fakes/README.md), so lookups key on this.
    """
    if not component_identifier:
        return None
    coords = component_identifier.get("coordinates", {})
    group = coords.get("groupId")
    artifact = coords.get("artifactId")
    version = coords.get("version")
    ext = coords.get("extension", "jar")
    if not (group and artifact and version):
        return None
    return f"pkg:maven/{group}/{artifact}@{version}?type={ext}"


@app.get("/api/v2/applications")
async def applications() -> dict[str, Any]:
    return {"applications": _DATA["applications"]}


# Added beyond the Task 7 brief's literal route list: Task 8's real IQ client
# needs a way to discover an application's *current* report id without
# already knowing one, because IqClient.create_determination's FindingRef
# carries no report_id or policyViolationId (see backend/app/adapters/iq/
# client.py's module docstring, design finding 3). This is a real, documented
# Sonatype endpoint (help.sonatype.com/en/report-rest-api.html, "Report REST
# APIs" — GET /api/v2/reports/applications/{applicationInternalId}, answering
# a per-stage summary whose reportDataUrl embeds the report id), added here
# per fakes/README.md's own standing policy: "If a real client needs a new
# fake route to be testable, add the smallest possible canned response for
# it." Not otherwise used by this fake's own tests.
@app.get("/api/v2/reports/applications/{application_id}")
async def application_reports(application_id: str) -> list[dict[str, Any]]:
    reports = _DATA["reports"].get(application_id, {})
    return [
        {
            "stage": "build",
            "applicationId": application_id,
            "evaluationDate": "2026-08-20T10:15:00.000-0700",
            "reportDataUrl": f"api/v2/applications/{application_id}/reports/{report_id}",
        }
        for report_id in reports
    ]


@app.get("/api/v2/applications/{application_id}/reports/{report_id}/raw")
async def raw_report(application_id: str, report_id: str) -> dict[str, Any]:
    try:
        return dict(_DATA["reports"][application_id][report_id]["raw"])
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="report not found") from exc


@app.get("/api/v2/applications/{application_id}/reports/{report_id}/policy")
async def policy_report(application_id: str, report_id: str) -> dict[str, Any]:
    try:
        return dict(_DATA["reports"][application_id][report_id]["policy"])
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="report not found") from exc


@app.get("/api/v2/vulnerabilities/{vulnerability_id}")
async def vulnerability(
    vulnerability_id: str,
    componentIdentifier: str | None = Query(default=None),  # noqa: N803 - vendor's own query param casing
) -> dict[str, Any]:
    try:
        return dict(_DATA["vulnerabilities"][vulnerability_id])
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="vulnerability not found") from exc


@app.post("/api/v2/components/remediation/application/{application_id}")
async def remediation(
    application_id: str,
    body: dict[str, Any],
    stageId: str | None = Query(default=None),  # noqa: N803 - vendor's own query param casing
) -> dict[str, Any]:
    purl = _purl_from_component_identifier(body.get("componentIdentifier"))
    entry = _DATA["remediation"].get(purl) if purl else None
    if entry is None:
        # A component IQ has never scanned has no remediation opinion at
        # all — real IQ's own "no remediation" signal is an empty
        # versionChanges array (see fakes/README.md), which is what a
        # component this fake DOES know about but cannot upgrade already
        # returns. An unrecognised component gets the same shape rather
        # than a special case, so the client never has to branch on "was
        # this component known" versus "was there nothing to recommend".
        return {"remediation": {"versionChanges": []}}
    return dict(entry)


@app.get("/api/v2/sourceControl/application/{application_id}")
async def get_source_control(application_id: str) -> dict[str, Any]:
    try:
        return dict(_DATA["source_control"][application_id])
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="no source control entry") from exc


@app.post("/api/v2/sourceControl/application/{application_id}", status_code=204)
async def create_source_control(application_id: str, body: dict[str, Any]) -> Response:
    # Sonatype's docs (help.sonatype.com/iqserver/automating/rest-apis/
    # source-control-rest-api---v2) document the request body but not this
    # response — 204 is chosen by analogy with every other IQ config-write
    # endpoint below, not confirmed against a real server. See
    # fakes/README.md.
    _DATA["source_control"][application_id] = {
        "id": _DATA["source_control"].get(application_id, {}).get("id", "generated-on-first-use"),
        "ownerId": application_id,
        **body,
    }
    return Response(status_code=204)


@app.post("/api/v2/policyWaivers/{owner_type}/{owner_id}", status_code=204)
async def create_waivers_bulk(owner_type: str, owner_id: str, body: dict[str, Any]) -> Response:
    options = body.get("apiWaiverOptionsDTO", {})
    for violation_id in body.get("violationIds", []):
        _record_waiver(owner_type, owner_id, violation_id, options)
    return Response(status_code=204)


@app.post("/api/v2/policyWaivers/{owner_type}/{owner_id}/{violation_id}", status_code=204)
async def create_waiver(
    owner_type: str, owner_id: str, violation_id: str, body: dict[str, Any]
) -> Response:
    _record_waiver(owner_type, owner_id, violation_id, body)
    return Response(status_code=204)


def _record_waiver(
    owner_type: str, owner_id: str, violation_id: str, options: dict[str, Any]
) -> None:
    waiver_id = hashlib.sha1(  # noqa: S324 - id generation, not a security use
        f"{violation_id}-{owner_id}-{time.time_ns()}".encode(), usedforsecurity=False
    ).hexdigest()[:32]
    violation = _VIOLATION_INDEX.get(violation_id, {})
    record = {
        "policyWaiverId": waiver_id,
        "policyViolationId": violation_id,
        "comment": options.get("comment", ""),
        "createTime": "2026-09-01T00:00:00.000+0000",
        "expiryTime": options.get("expiryTime"),
        "scopeOwnerType": owner_type,
        "scopeOwnerId": owner_id,
        "hash": violation.get("hash"),
        "policyId": violation.get("policyId"),
        "vulnerabilityId": _cve_for_violation(violation),
        "matcherStrategy": options.get("matcherStrategy", "EXACT_COMPONENT"),
        "associatedPackageUrl": violation.get("packageUrl"),
        "policyWaiverReasonId": options.get("waiverReasonId"),
        "expireWhenRemediationAvailable": options.get("expireWhenRemediationAvailable", False),
    }
    _waivers[waiver_id] = record
    _waivers_by_violation.setdefault(violation_id, []).append(waiver_id)


def _cve_for_violation(violation: dict[str, Any]) -> str | None:
    for constraint in violation.get("constraintViolations", []):
        for reason in constraint.get("reasons", []):
            ref = reason.get("reference", {})
            if ref.get("type") == "SECURITY_VULNERABILITY_REFID":
                value: str | None = ref.get("value")
                return value
    return None


@app.delete("/api/v2/policyWaivers/{owner_type}/{owner_id}/{waiver_id}", status_code=204)
async def delete_waiver(owner_type: str, owner_id: str, waiver_id: str) -> Response:
    record = _waivers.pop(waiver_id, None)
    if record is None:
        raise HTTPException(status_code=404, detail="waiver not found")
    violation_id = record["policyViolationId"]
    _waivers_by_violation.get(violation_id, []).remove(waiver_id)
    return Response(status_code=204)


@app.get("/api/v2/policyViolations/{violation_id}/applicableWaivers")
async def applicable_waivers(violation_id: str) -> dict[str, Any]:
    active = [_waivers[wid] for wid in _waivers_by_violation.get(violation_id, [])]
    return {"activeWaivers": active, "expiredWaivers": []}


@app.get("/api/v2/waiverReasons")
async def waiver_reasons() -> dict[str, Any]:
    return dict(_DATA["waiver_reasons"])
