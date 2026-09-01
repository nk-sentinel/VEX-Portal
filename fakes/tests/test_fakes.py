"""Tests for the four throwaway fake servers.

NOT part of backend's pytest suite and NOT counted in its 280 tests — these
exercise fakes/, a separate, disposable directory that backend/app/ must
never import (see /fakes/README.md). Run from the repo root:

    PYTHONPATH=. backend/.venv/bin/python -m pytest fakes/tests -q

Two layers, on purpose:

1. In-process route tests (via FastAPI's TestClient) covering every
   documented route, including the cross-fake consistency the brief singles
   out — JFrog's artifact hashes must MATCH what IQ's report claims, and
   feeding both through the REAL evidence engine (app.evidence.pack) must
   produce the three required outcomes (not-affected / affected /
   ambiguous). That last test is the one that would catch a fake that
   returns a "convenient" shape instead of the vendor's real one: a wrong
   nesting or wrong field name breaks the real client-side parsing this is
   meant to stand in for, not just this test file.
2. One real-subprocess-over-real-HTTP smoke test per fake, because
   "answers over real HTTP" and "an in-process ASGI call succeeds" are not
   the same claim — see the Task 7 brief's own test checkbox.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import zipfile
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPO_ROOT / "backend"
for _path in (REPO_ROOT, BACKEND_ROOT):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from app.adapters.protocols import AiVerdictDto  # noqa: E402
from app.domain.determination import Confidence, Justification, State  # noqa: E402
from app.evidence.pack import build_pack  # noqa: E402
from app.provenance.fingerprint import Verdict  # noqa: E402

from fakes.bedrock.main import app as bedrock_app  # noqa: E402
from fakes.bitbucket.main import app as bitbucket_app  # noqa: E402
from fakes.iq.main import app as iq_app  # noqa: E402
from fakes.jfrog.main import app as jfrog_app  # noqa: E402

APP_ID = "4f6d8a2c9b1e4a7f8c3d2b1a0f9e8d7c"
REPORT_ID = "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"


@pytest.fixture
def iq() -> Iterator[TestClient]:
    with TestClient(iq_app) as client:
        yield client


@pytest.fixture
def jfrog() -> Iterator[TestClient]:
    with TestClient(jfrog_app) as client:
        yield client


@pytest.fixture
def bitbucket() -> Iterator[TestClient]:
    with TestClient(bitbucket_app) as client:
        yield client


@pytest.fixture
def bedrock() -> Iterator[TestClient]:
    with TestClient(bedrock_app) as client:
        yield client


# --- fake IQ ---------------------------------------------------------------


def test_iq_applications_lists_the_sample_app(iq: TestClient) -> None:
    body = iq.get("/api/v2/applications").json()
    assert body["applications"][0]["id"] == APP_ID
    assert body["applications"][0]["name"] == "Payments API"


def test_iq_raw_report_shape_matches_documented_component_fields(iq: TestClient) -> None:
    body = iq.get(f"/api/v2/applications/{APP_ID}/reports/{REPORT_ID}/raw").json()
    components = body["components"]
    assert len(components) == 7
    for component in components:
        assert set(component) >= {
            "hash",
            "componentIdentifier",
            "packageUrl",
            "matchState",
            "pathnames",
            "securityData",
        }
        assert len(component["hash"]) == 40  # sha1 hex digest


def test_iq_raw_report_404_for_unknown_report(iq: TestClient) -> None:
    resp = iq.get(f"/api/v2/applications/{APP_ID}/reports/does-not-exist/raw")
    assert resp.status_code == 404


def test_iq_policy_report_has_the_three_required_finding_shapes(iq: TestClient) -> None:
    body = iq.get(f"/api/v2/applications/{APP_ID}/reports/{REPORT_ID}/policy").json()
    violations_by_cve = {}
    for component in body["components"]:
        for violation in component["violations"]:
            cve = violation["constraintViolations"][0]["reasons"][0]["reference"]["value"]
            violations_by_cve[cve] = {"purl": component["packageUrl"], **violation}
    assert set(violations_by_cve) == {"CVE-2022-42889", "CVE-2021-44228", "CVE-2015-6420"}
    for violation in violations_by_cve.values():
        assert violation["policyViolationId"]
        assert violation["policyId"]
        assert isinstance(violation["threatLevel"], int)


def test_iq_vulnerability_carries_kev_epss_severity_and_root_causes(iq: TestClient) -> None:
    kev = iq.get("/api/v2/vulnerabilities/CVE-2022-42889").json()
    assert kev["kevData"]["isKev"] is True
    assert kev["mainSeverity"]["score"] == pytest.approx(9.8)
    assert kev["rootCauses"][0]["listOfPaths"] == [
        "org/apache/commons/text/StringSubstitutor.class"
    ]

    high_epss = iq.get("/api/v2/vulnerabilities/CVE-2021-44228").json()
    assert high_epss["epssData"]["currentScore"] > 0.9

    no_fix_candidate = iq.get("/api/v2/vulnerabilities/CVE-2015-6420").json()
    assert no_fix_candidate["kevData"]["isKev"] is False


def test_iq_vulnerability_404_for_unknown_cve(iq: TestClient) -> None:
    assert iq.get("/api/v2/vulnerabilities/CVE-0000-00000").status_code == 404


def test_iq_remediation_returns_a_fix_version_when_one_exists(iq: TestClient) -> None:
    body = iq.post(
        f"/api/v2/components/remediation/application/{APP_ID}",
        json={
            "componentIdentifier": {
                "format": "maven",
                "coordinates": {
                    "groupId": "org.apache.commons",
                    "artifactId": "commons-text",
                    "version": "1.9",
                    "extension": "jar",
                },
            }
        },
    ).json()
    changes = body["remediation"]["versionChanges"]
    assert changes
    assert changes[0]["data"]["component"]["componentIdentifier"]["coordinates"]["version"] == (
        "1.10.0"
    )


def test_iq_remediation_reports_no_fix_available_as_an_empty_list(iq: TestClient) -> None:
    # This is the "no fix available" sample the brief requires — represented
    # the way Sonatype's own docs say IQ represents it: an empty
    # versionChanges array, not a null or a special-cased field.
    body = iq.post(
        f"/api/v2/components/remediation/application/{APP_ID}",
        json={
            "componentIdentifier": {
                "format": "maven",
                "coordinates": {
                    "groupId": "commons-collections",
                    "artifactId": "commons-collections",
                    "version": "3.2.1",
                    "extension": "jar",
                },
            }
        },
    ).json()
    assert body["remediation"]["versionChanges"] == []


def test_iq_source_control_get_returns_repository_and_base_branch(iq: TestClient) -> None:
    body = iq.get(f"/api/v2/sourceControl/application/{APP_ID}").json()
    assert body["repositoryUrl"].startswith("https://bitbucket.example.internal/")
    assert body["baseBranch"] == "release/2026.09"


def test_iq_source_control_post_then_get_roundtrips(iq: TestClient) -> None:
    resp = iq.post(
        f"/api/v2/sourceControl/application/{APP_ID}",
        json={
            "provider": "bitbucket",
            "repositoryUrl": "https://bitbucket.example.internal/scm/pay/payments-api.git",
            "baseBranch": "main",
        },
    )
    assert resp.status_code == 204
    body = iq.get(f"/api/v2/sourceControl/application/{APP_ID}").json()
    assert body["baseBranch"] == "main"


def test_iq_waiver_reasons_returns_structured_reasons(iq: TestClient) -> None:
    body = iq.get("/api/v2/waiverReasons").json()
    assert body["waiverReasons"]
    assert all({"id", "reasonText"} <= set(reason) for reason in body["waiverReasons"])


def test_iq_waiver_create_list_delete_roundtrips(iq: TestClient) -> None:
    policy = iq.get(f"/api/v2/applications/{APP_ID}/reports/{REPORT_ID}/policy").json()
    violation_id = next(
        v["policyViolationId"]
        for c in policy["components"]
        for v in c["violations"]
        if c["packageUrl"] == "pkg:maven/org.apache.commons/commons-text@1.9?type=jar"
    )

    create = iq.post(
        f"/api/v2/policyWaivers/application/{APP_ID}",
        json={
            "violationIds": [violation_id],
            "apiWaiverOptionsDTO": {
                "comment": "assessment-123: not reachable",
                "waiverReasonId": "878fa8a3d01185b45664c4e6ab9a92a3",
                "expiryTime": "2026-09-08T00:00:00.000+0000",
                "expireWhenRemediationAvailable": True,
            },
        },
    )
    assert create.status_code == 204  # matches Sonatype's documented behaviour: no id in the body

    applicable = iq.get(f"/api/v2/policyViolations/{violation_id}/applicableWaivers").json()
    assert len(applicable["activeWaivers"]) == 1
    waiver_id = applicable["activeWaivers"][0]["policyWaiverId"]
    assert waiver_id

    delete = iq.delete(f"/api/v2/policyWaivers/application/{APP_ID}/{waiver_id}")
    assert delete.status_code == 204

    applicable_after = iq.get(f"/api/v2/policyViolations/{violation_id}/applicableWaivers").json()
    assert applicable_after["activeWaivers"] == []


# --- fake JFrog --------------------------------------------------------------


def test_jfrog_build_info_carries_vcs_url_revision_branch(jfrog: TestClient) -> None:
    body = jfrog.get("/api/build/payments-api/247").json()
    vcs = body["buildInfo"]["vcs"][0]
    assert vcs["url"] == "https://bitbucket.example.internal/scm/pay/payments-api.git"
    assert vcs["branch"] == "release/2026.09"
    assert len(vcs["revision"]) == 40


def test_jfrog_build_info_404_for_unknown_build(jfrog: TestClient) -> None:
    assert jfrog.get("/api/build/payments-api/999").status_code == 404


def test_jfrog_fetch_returns_a_real_parseable_spring_boot_jar(jfrog: TestClient) -> None:
    resp = jfrog.get("/libs-release-local/com/example/payments-api/1.0.0/payments-api-1.0.0.jar")
    assert resp.status_code == 200
    archive = zipfile.ZipFile(BytesIO(resp.content))
    names = archive.namelist()
    assert any(n.startswith("BOOT-INF/lib/") for n in names)
    assert any(n.startswith("BOOT-INF/classes/") for n in names)


def test_jfrog_fetch_ignores_coordinates_and_always_returns_the_sample_artifact(
    jfrog: TestClient,
) -> None:
    first = jfrog.get("/any/path/at/all.jar").content
    second = jfrog.get("/a-totally-different-path.jar").content
    assert first == second


# --- cross-fake consistency (the "provenance MATCH" requirement) -----------


def test_jfrog_artifact_library_hashes_match_what_iq_reports(
    jfrog: TestClient, iq: TestClient
) -> None:
    artifact = jfrog.get("/whatever.jar").content
    archive = zipfile.ZipFile(BytesIO(artifact))
    artifact_hashes = {
        hashlib.sha1(archive.read(name), usedforsecurity=False).hexdigest()
        for name in archive.namelist()
        if name.startswith("BOOT-INF/lib/")
    }

    raw = iq.get(f"/api/v2/applications/{APP_ID}/reports/{REPORT_ID}/raw").json()
    report_hashes = {c["hash"] for c in raw["components"]}

    assert artifact_hashes == report_hashes
    assert len(report_hashes) == 7


def test_evidence_engine_produces_the_three_required_outcomes_from_the_fakes(
    jfrog: TestClient, iq: TestClient
) -> None:
    """The test that matters: feed the REAL evidence engine exactly what the
    real client would get from these fakes and check the three narrative
    outcomes the brief requires actually fall out — not asserted by
    construction here, but recomputed by app.evidence.pack against bytes
    and JSON served over the fakes' own HTTP routes.
    """
    artifact = jfrog.get("/whatever.jar").content
    raw = iq.get(f"/api/v2/applications/{APP_ID}/reports/{REPORT_ID}/raw").json()
    policy = iq.get(f"/api/v2/applications/{APP_ID}/reports/{REPORT_ID}/policy").json()

    report_hashes = {c["hash"] for c in raw["components"]}

    findings: dict[str, list[str]] = {}
    for component in policy["components"]:
        for violation in component["violations"]:
            cve = violation["constraintViolations"][0]["reasons"][0]["reference"]["value"]
            vuln = iq.get(f"/api/v2/vulnerabilities/{cve}").json()
            findings[cve] = [
                path
                for cause in vuln["rootCauses"]
                for path in cause["listOfPaths"]
            ]

    pack = build_pack(artifact, report_hashes, findings)

    assert pack.provenance.verdict is Verdict.MATCH

    by_cve = {c.cve: c for c in pack.components}

    # Clearly affected: class ships AND the application references it.
    affected = by_cve["CVE-2022-42889"]
    assert affected.class_present is True
    assert affected.referenced is True

    # Genuinely ambiguous: class ships, not directly referenced, but a
    # reflection escape hatch elsewhere makes "not referenced" untrustworthy.
    ambiguous = by_cve["CVE-2021-44228"]
    assert ambiguous.class_present is True
    assert ambiguous.referenced is False
    assert ambiguous.reference_scan_conclusive is False

    # Clearly not affected: the vulnerable class never ships in this build.
    not_affected = by_cve["CVE-2015-6420"]
    assert not_affected.class_present is False

    assert any(hatch.kind == "reflection" for hatch in pack.escape_hatches)


# --- fake Bitbucket ----------------------------------------------------------


def test_bitbucket_raw_file_returns_the_source_containing_the_vulnerable_reference(
    bitbucket: TestClient,
) -> None:
    resp = bitbucket.get(
        "/rest/api/1.0/projects/PAY/repos/payments-api/raw/"
        "src/main/java/com/example/payments/PaymentService.java",
        params={"at": "release/2026.09"},
    )
    assert resp.status_code == 200
    assert "StringSubstitutor" in resp.text


def test_bitbucket_raw_file_404_for_unknown_path(bitbucket: TestClient) -> None:
    resp = bitbucket.get(
        "/rest/api/1.0/projects/PAY/repos/payments-api/raw/does/not/exist.java"
    )
    assert resp.status_code == 404


def test_bitbucket_search_finds_the_stringsubstitutor_reference(bitbucket: TestClient) -> None:
    body = bitbucket.post(
        "/rest/search/latest/search",
        json={"query": "StringSubstitutor", "entities": {"code": {}}},
    ).json()
    assert body["code"]["count"] == 1
    hit = body["code"]["values"][0]
    assert hit["file"]["path"]["toString"].endswith("PaymentService.java")
    assert hit["hitContexts"][0][0]["line"] > 0


def test_bitbucket_search_no_hits_for_a_symbol_that_is_not_present(bitbucket: TestClient) -> None:
    body = bitbucket.post(
        "/rest/search/latest/search",
        json={"query": "JndiLookup", "entities": {"code": {}}},
    ).json()
    assert body["code"]["count"] == 0


# --- fake Bedrock -------------------------------------------------------------


def _invoke(bedrock: TestClient, mentioning: str) -> dict:
    return bedrock.post(
        "/model/anthropic.claude-opus-5-20260101-v1:0/invoke",
        json={
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": f"Adjudicate finding for {mentioning}."}],
        },
    ).json()


def test_bedrock_response_is_the_anthropic_messages_envelope(bedrock: TestClient) -> None:
    body = _invoke(bedrock, "CVE-2022-42889")
    assert body["type"] == "message"
    assert body["role"] == "assistant"
    assert body["model"] == "anthropic.claude-opus-5-20260101-v1:0"
    assert body["stop_reason"] == "tool_use"
    assert body["content"][0]["type"] == "tool_use"
    assert "usage" in body and "input_tokens" in body["usage"]


def test_bedrock_returns_a_verdict_the_domain_types_accept_for_every_canned_case(
    bedrock: TestClient,
) -> None:
    for cve in ("CVE-2022-42889", "CVE-2021-44228", "CVE-2015-6420", "CVE-9999-does-not-exist"):
        body = _invoke(bedrock, cve)
        verdict_input = body["content"][0]["input"]
        # This is the strict-output contract check: the canned tool input
        # must actually construct AiVerdictDto through the portal's own
        # closed enums, not merely look like the right JSON shape.
        dto = AiVerdictDto(
            state=State(verdict_input["state"]),
            justification=(
                Justification(verdict_input["justification"])
                if verdict_input["justification"]
                else None
            ),
            confidence=Confidence(verdict_input["confidence"]),
            evidence_refs=verdict_input["evidence_refs"],
            missing_evidence=verdict_input["missing_evidence"],
        )
        assert dto.state in State


def test_bedrock_abstains_for_the_ambiguous_finding(bedrock: TestClient) -> None:
    body = _invoke(bedrock, "CVE-2021-44228")
    verdict_input = body["content"][0]["input"]
    assert verdict_input["confidence"] == "insufficient_evidence"
    assert Confidence(verdict_input["confidence"]).abstains()


def test_bedrock_abstains_by_default_for_an_unrecognised_finding(bedrock: TestClient) -> None:
    body = _invoke(bedrock, "CVE-9999-does-not-exist")
    verdict_input = body["content"][0]["input"]
    assert verdict_input["confidence"] == "insufficient_evidence"
    assert verdict_input["missing_evidence"]


def test_bedrock_returns_affected_high_confidence_for_the_clear_cut_case(
    bedrock: TestClient,
) -> None:
    body = _invoke(bedrock, "CVE-2022-42889")
    verdict_input = body["content"][0]["input"]
    assert verdict_input["state"] == "affected"
    assert verdict_input["confidence"] == "high"


# --- real-process smoke tests (over real HTTP, not just in-process ASGI) ---


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_listening(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            try:
                s.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(0.1)
    raise TimeoutError(f"nothing listening on 127.0.0.1:{port} after {timeout}s")


@pytest.mark.parametrize(
    ("module", "probe"),
    [
        ("fakes.iq.main", lambda base: httpx.get(f"{base}/api/v2/applications")),
        ("fakes.jfrog.main", lambda base: httpx.get(f"{base}/api/build/payments-api/247")),
        (
            "fakes.bitbucket.main",
            lambda base: httpx.post(
                f"{base}/rest/search/latest/search",
                json={"query": "StringSubstitutor", "entities": {"code": {}}},
            ),
        ),
        (
            "fakes.bedrock.main",
            lambda base: httpx.post(
                f"{base}/model/anthropic.claude-opus-5-20260101-v1:0/invoke",
                json={"messages": [{"role": "user", "content": "hello"}]},
            ),
        ),
    ],
)
def test_fake_starts_as_a_real_process_and_answers_over_real_http(module, probe) -> None:
    port = _free_port()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            f"{module}:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
    )
    try:
        _wait_until_listening(port)
        response = probe(f"http://127.0.0.1:{port}")
        assert response.status_code == 200
        json.loads(response.content)  # a real, valid JSON body came back
    finally:
        process.terminate()
        process.wait(timeout=10)
