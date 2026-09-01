"""Shared plumbing for the four fake servers.

THROWAWAY — see fakes/README.md. Not imported by anything under
backend/app/. This module only exists so each fake's main.py can load its
canned JSON/binary data with one line instead of four.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent / "data"


def load_json(name: str) -> Any:
    """Load one of the canned data files in fakes/data/ by filename."""
    with (DATA_DIR / name).open(encoding="utf-8") as f:
        return json.load(f)


def sample_artifact_bytes() -> bytes:
    """The pre-built Spring Boot fat JAR fakes/jfrog serves.

    Built once (see fakes/data/README in fakes/README.md's "Regenerating the
    sample artifact" section) with the real test factories in
    backend/tests/artifact/factories.py, then checked in as a binary fixture.
    Built once rather than on every fake startup because
    zipfile.ZipFile.writestr() stamps each entry with the current wall-clock
    time by default, which would make the artifact's own bytes — and every
    SHA-1 derived from them — different on every process start. fakes/iq's
    component hashes are computed from this exact file (see
    fakes/data/iq.json), so JFrog and IQ can only stay in agreement if both
    read the same static bytes instead of each generating their own.
    """
    return (DATA_DIR / "sample-artifact.jar").read_bytes()
