"""Inspect a real artifact from the command line.

Not part of the service. It exists so the team can point the evidence engine at
an actual JAR, WAR, or recovered image archive and see exactly what it observes
— which is the fastest way to diagnose a determination that looks wrong.

    python -m app.artifact.cli path/to/app.jar
    python -m app.artifact.cli path/to/app.jar org/apache/commons/text/StringSubstitutor
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from app.artifact.errors import ArtifactError
from app.artifact.inventory import inspect_archive
from app.artifact.presence import contains_class
from app.artifact.references import scan_references


def main(argv: list[str]) -> int:
    if not 2 <= len(argv) <= 3:
        print(__doc__, file=sys.stderr)
        return 2

    path = Path(argv[1])
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"could not read {path}: {exc}", file=sys.stderr)
        return 1

    try:
        inventory = inspect_archive(data)
        scan = scan_references(inventory)
        report: dict[str, object] = {
            "layout": inventory.layout.value,
            "libraries": len(inventory.libraries),
            "app_classes": len(inventory.app_classes),
            "classes_scanned": scan.classes_scanned,
            "unreadable_classes": scan.unreadable_classes,
            "commit_sha": inventory.commit_sha(),
            "repository_url": inventory.repository_url(),
            "escape_hatches": sorted({hatch.kind for hatch in scan.escape_hatches}),
            "reference_scan_conclusive": scan.is_conclusive(),
        }
        if len(argv) == 3:
            target = argv[2]
            report["query"] = {
                "class": target,
                "present_in_artifact": contains_class(data, target),
                "referenced_by_application": scan.references(target),
            }
    except ArtifactError as exc:
        print(f"could not inspect {path}: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
