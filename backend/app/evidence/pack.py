"""Assemble collected facts into the structure the rule engine consumes.

The rule engine is deliberately given facts, never questions. Everything here
is observation — what ships, what is referenced, whether the artifact matches
the report. No rule is applied, no tier is assigned, and no conclusion is
drawn; those belong to the rule engine, which is the only place the tier rules
are enforced.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.artifact.inventory import inspect_archive
from app.artifact.presence import contains_class
from app.artifact.references import EscapeHatch, scan_references
from app.provenance.fingerprint import FingerprintResult, compare


@dataclass(frozen=True, slots=True)
class ComponentEvidence:
    """What was observed about one finding."""

    cve: str

    #: The implicated class paths, as reported in rootCauses[].listOfPaths.
    class_paths: list[str]

    #: True if any implicated class ships in the artifact. False is Tier 1
    #: proof that the vulnerability cannot execute.
    class_present: bool

    #: True if the application's own bytecode references any implicated class.
    referenced: bool

    #: Whether absence of a reference can be trusted. False when a
    #: dynamic-dispatch escape hatch was found or a class failed to parse — in
    #: which case ``referenced=False`` is not evidence of anything.
    reference_scan_conclusive: bool


@dataclass(frozen=True, slots=True)
class EvidencePack:
    """Everything observed about one artifact and its findings."""

    provenance: FingerprintResult
    inventory_summary: dict[str, object] = field(default_factory=dict)
    components: list[ComponentEvidence] = field(default_factory=list)
    escape_hatches: list[EscapeHatch] = field(default_factory=list)


def build_pack(
    artifact: bytes,
    report_component_sha1s: set[str],
    findings: dict[str, list[str]],
) -> EvidencePack:
    """Collect every offline fact about ``artifact`` relevant to ``findings``.

    Args:
        artifact: the JAR or WAR bytes. For a containerised application this is
            the archive recovered by :mod:`app.artifact.image`.
        report_component_sha1s: SHA-1 hashes of components in the scan report.
        findings: CVE identifier mapped to its implicated class paths.

    Raises:
        MalformedArtifact: the artifact could not be read. Callers must not
            treat this as evidence of absence.
    """
    inventory = inspect_archive(artifact)
    provenance = compare(report_component_sha1s, inventory)
    scan = scan_references(inventory)

    components = [
        ComponentEvidence(
            cve=cve,
            class_paths=list(class_paths),
            class_present=any(contains_class(artifact, path) for path in class_paths),
            referenced=any(scan.references(path) for path in class_paths),
            reference_scan_conclusive=scan.is_conclusive(),
        )
        for cve, class_paths in sorted(findings.items())
    ]

    return EvidencePack(
        provenance=provenance,
        inventory_summary={
            "layout": inventory.layout.value,
            "libraries": len(inventory.libraries),
            "app_classes": len(inventory.app_classes),
            "classes_scanned": scan.classes_scanned,
            "unreadable_classes": len(scan.unreadable_classes),
            "commit_sha": inventory.commit_sha(),
            "repository_url": inventory.repository_url(),
        },
        components=components,
        escape_hatches=scan.escape_hatches,
    )
