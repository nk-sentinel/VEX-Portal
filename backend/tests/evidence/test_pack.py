import hashlib

import pytest

from app.artifact.errors import MalformedArtifact
from app.evidence.pack import build_pack
from app.provenance.fingerprint import Verdict
from tests.artifact.factories import make_class_file, make_jar, make_spring_boot_jar

VULNERABLE_CLASS = "org/apache/commons/text/StringSubstitutor.class"


def _artifact_with_vulnerable_library():
    vulnerable_lib = make_jar({VULNERABLE_CLASS: b"y" * 512})
    others = {f"lib-{i}.jar": make_jar({f"pkg/C{i}.class": bytes([i])}) for i in range(9)}
    libraries = {"commons-text-1.9.jar": vulnerable_lib, **others}
    artifact = make_spring_boot_jar(
        app_classes={"com/example/App.class": make_class_file(["java/lang/String"])},
        libraries=libraries,
    )
    report_hashes = {hashlib.sha1(p).hexdigest() for p in libraries.values()}
    return artifact, report_hashes


def test_pack_reports_class_present_but_unreferenced():
    artifact, report_hashes = _artifact_with_vulnerable_library()

    pack = build_pack(
        artifact,
        report_component_sha1s=report_hashes,
        findings={"CVE-2022-42889": [VULNERABLE_CLASS]},
    )

    assert pack.provenance.verdict is Verdict.MATCH
    evidence = pack.components[0]
    assert evidence.cve == "CVE-2022-42889"
    assert evidence.class_present is True
    assert evidence.referenced is False
    assert evidence.reference_scan_conclusive is True


def test_pack_reports_class_absent_when_it_does_not_ship():
    artifact, report_hashes = _artifact_with_vulnerable_library()

    pack = build_pack(
        artifact,
        report_component_sha1s=report_hashes,
        findings={"CVE-9999-0001": ["com/absent/Nothing.class"]},
    )

    assert pack.components[0].class_present is False


def test_pack_marks_scan_inconclusive_when_an_escape_hatch_is_present():
    vulnerable_lib = make_jar({VULNERABLE_CLASS: b"y" * 512})
    libraries = {
        "commons-text-1.9.jar": vulnerable_lib,
        **{f"l{i}.jar": make_jar({f"p/C{i}.class": bytes([i])}) for i in range(9)},
    }
    artifact = make_spring_boot_jar(
        app_classes={"com/example/App.class": make_class_file(["java/lang/Class"])},
        libraries=libraries,
    )
    report_hashes = {hashlib.sha1(p).hexdigest() for p in libraries.values()}

    pack = build_pack(
        artifact, report_component_sha1s=report_hashes, findings={"CVE-1": [VULNERABLE_CLASS]}
    )

    assert pack.components[0].reference_scan_conclusive is False
    assert any(h.kind == "reflection" for h in pack.escape_hatches)


def test_pack_records_provenance_mismatch():
    artifact, _ = _artifact_with_vulnerable_library()
    unrelated = {hashlib.sha1(f"x{i}".encode()).hexdigest() for i in range(10)}

    pack = build_pack(artifact, report_component_sha1s=unrelated, findings={})

    assert pack.provenance.verdict is Verdict.MISMATCH


def test_finding_with_several_class_paths_is_present_if_any_ships():
    artifact, report_hashes = _artifact_with_vulnerable_library()

    pack = build_pack(
        artifact,
        report_component_sha1s=report_hashes,
        findings={"CVE-2": ["com/absent/A.class", VULNERABLE_CLASS]},
    )

    assert pack.components[0].class_present is True


def test_unreadable_artifact_propagates_rather_than_yielding_an_empty_pack():
    # "Could not read" must never become "nothing found". Absence of a class
    # is Tier 1 proof that clears a security finding, so a pack built from a
    # failed read would manufacture that proof out of an I/O error.
    with pytest.raises(MalformedArtifact):
        build_pack(b"not a zip file at all", set(), {"CVE-2022-42889": [VULNERABLE_CLASS]})


def test_referenced_is_true_when_the_application_names_the_class():
    vulnerable_lib = make_jar({VULNERABLE_CLASS: b"y" * 512})
    others = {f"lib-{i}.jar": make_jar({f"pkg/C{i}.class": bytes([i])}) for i in range(9)}
    libraries = {"commons-text-1.9.jar": vulnerable_lib, **others}
    artifact = make_spring_boot_jar(
        app_classes={
            "com/example/App.class": make_class_file(
                ["org/apache/commons/text/StringSubstitutor", "java/lang/String"]
            )
        },
        libraries=libraries,
    )
    report_hashes = {
        hashlib.sha1(p, usedforsecurity=False).hexdigest() for p in libraries.values()
    }

    pack = build_pack(artifact, report_hashes, {"CVE-2022-42889": [VULNERABLE_CLASS]})

    evidence = pack.components[0]
    assert evidence.referenced is True
    assert evidence.reference_scan_conclusive is True


def test_components_are_ordered_by_cve():
    artifact, report_hashes = _artifact_with_vulnerable_library()
    findings = {
        "CVE-2023-0003": ["com/absent/C.class"],
        "CVE-2021-0001": ["com/absent/A.class"],
        "CVE-2022-0002": ["com/absent/B.class"],
    }

    pack = build_pack(artifact, report_hashes, findings)

    assert [c.cve for c in pack.components] == ["CVE-2021-0001", "CVE-2022-0002", "CVE-2023-0003"]


def test_inventory_summary_reports_embedded_provenance():
    lib = make_jar({"p/C.class": b"c" * 64})
    artifact = make_spring_boot_jar(
        app_classes={"com/example/App.class": make_class_file(["java/lang/String"])},
        libraries={"dep.jar": lib},
        git_properties={
            "git.commit.id.full": "4a9f1c2e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39",
            "git.remote.origin.url": "https://bitbucket.example/scm/pay/payments-api.git",
        },
    )

    summary = build_pack(artifact, set(), {}).inventory_summary

    assert summary["commit_sha"] == "4a9f1c2e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39"
    assert summary["repository_url"] == "https://bitbucket.example/scm/pay/payments-api.git"
    assert summary["layout"] == "spring-boot-fat"
    assert summary["libraries"] == 1
    assert summary["app_classes"] == 1


def test_inventory_summary_reports_none_when_provenance_is_absent():
    # Must be None, never "" or a stale value — a caller distinguishing
    # "no commit recorded" from "commit recorded as empty" depends on it.
    artifact = make_spring_boot_jar(
        app_classes={"com/example/App.class": make_class_file(["java/lang/String"])},
        libraries={"dep.jar": make_jar({"p/C.class": b"c" * 64})},
    )

    summary = build_pack(artifact, set(), {}).inventory_summary

    assert summary["commit_sha"] is None
    assert summary["repository_url"] is None
