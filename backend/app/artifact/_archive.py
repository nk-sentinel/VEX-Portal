"""Shared internals for walking ZIP-based artifacts.

:mod:`app.artifact.presence` and :mod:`app.artifact.inventory` each implement
their own walk of the same ZIP structure for different purposes — Tier 1
presence versus inventory collection — and used to carry independent copies
of the resource-bound bookkeeping, the read-failure exception tuple, and the
recognised nested-archive suffixes. Independently-written copies drift:
presence.py's suffix test was lowercased and inventory.py's was not, which
made an uppercase-named bundled library (``EVIL.JAR``) visible to one check
and invisible to the other. This module exists so there is exactly one copy
of each to import, not two that can grow apart again.
"""

from __future__ import annotations

import io
import zipfile
import zlib
from dataclasses import dataclass

from app.artifact.errors import ArtifactTooLarge, MalformedArtifact
from app.artifact.limits import Limits

#: A corrupt archive can fail in any of these ways depending on where the
#: corruption lands — a bad central directory, a truncated deflate stream, an
#: unsupported compression method, an encrypted entry. All of them are "we
#: could not read this", never "the class is not present" or "the entry is
#: empty", so every one of them is converted to MalformedArtifact rather than
#: left to escape raw or be swallowed.
READ_FAILURES: tuple[type[Exception], ...] = (
    zipfile.BadZipFile,
    zlib.error,
    OSError,
    RuntimeError,
    NotImplementedError,
    EOFError,
)

#: Recognised archive extensions. Always test with :func:`has_archive_suffix`,
#: never a bare ``.endswith()`` — a build tool is free to name an artifact
#: ``app.JAR`` or ``app.War``; the JVM does not care about case, so neither
#: can this.
ARCHIVE_SUFFIXES = (".jar", ".war", ".ear")


def has_archive_suffix(name: str) -> bool:
    """Whether ``name`` ends in a recognised archive extension, case-insensitively."""
    return name.lower().endswith(ARCHIVE_SUFFIXES)


@dataclass(slots=True)
class Budget:
    """Running totals for one archive walk, shared across nested recursion.

    A single instance is threaded through an entire walk — including every
    recursive descent into a nested archive — so the limits in
    :class:`app.artifact.limits.Limits` bound the cost of the walk as a
    whole, not just one archive within it.
    """

    entries: int = 0
    total_uncompressed: int = 0


def enforce_limits(info: zipfile.ZipInfo, budget: Budget, limits: Limits) -> None:
    """Reject a declared-oversized or bomb-shaped entry before it is read.

    Checked against declared metadata (``file_size`` / ``compress_size``)
    before any entry is decompressed, so a bomb is refused rather than read
    and then rejected.
    """
    budget.entries += 1
    if budget.entries > limits.max_entries:
        raise ArtifactTooLarge(f"archive has more than {limits.max_entries} entries")
    if info.file_size > limits.max_entry_size:
        raise ArtifactTooLarge(
            f"entry {info.filename!r} declares {info.file_size} bytes, over the "
            f"{limits.max_entry_size} byte limit"
        )
    ratio = info.file_size / max(info.compress_size, 1)
    if ratio > limits.max_compression_ratio:
        raise ArtifactTooLarge(
            f"entry {info.filename!r} has compression ratio {ratio:.0f}:1, over the "
            f"{limits.max_compression_ratio}:1 limit"
        )
    budget.total_uncompressed += info.file_size
    if budget.total_uncompressed > limits.max_total_uncompressed:
        raise ArtifactTooLarge(
            f"archive exceeds {limits.max_total_uncompressed} total uncompressed bytes"
        )


def open_zip(data: bytes) -> zipfile.ZipFile:
    """Open ``data`` as a ZIP, converting a corrupt-archive failure into MalformedArtifact."""
    try:
        return zipfile.ZipFile(io.BytesIO(data))
    except READ_FAILURES as exc:
        raise MalformedArtifact(f"not a readable archive: {exc}") from exc


def read_entry(archive: zipfile.ZipFile, name: str) -> bytes:
    """Read one entry, converting a corrupt-archive failure into MalformedArtifact.

    An untyped exception escaping here would be handled by a caller as an
    unknown error rather than as "evidence could not be collected", which is
    a different decision — see the callers' module docstrings.
    """
    try:
        return archive.read(name)
    except READ_FAILURES as exc:
        raise MalformedArtifact(f"could not read {name!r}: {exc}") from exc
