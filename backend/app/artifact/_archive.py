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

import copy
import io
import zipfile
import zlib
from collections import Counter
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


#: Overrides a lied-about declared uncompressed size in
#: read_entry_ignoring_declared_size. Large enough that no legitimate or
#: attacker-inflated entry's real decompressed length could reach it; its
#: only job is to stop zipfile from truncating the bytes it returns to the
#: (attacker-controlled) declared size, so the natural end of the compressed
#: stream decides where the read stops instead.
_UNBOUNDED_ENTRY_SIZE = 1 << 62


def read_entry_ignoring_declared_size(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """Read one entry's true payload, ignoring its declared uncompressed size.

    ``ZipInfo.file_size`` is the ZIP central directory's DECLARED
    uncompressed size — attacker-controlled metadata, not a fact about the
    entry. ``zipfile.ZipFile.read`` trusts it as a hard cap on the bytes it
    returns: internally, every decompressed chunk is sliced to
    ``data[:self._left]`` where ``self._left`` starts at ``zinfo.file_size``
    and never grows. So an entry that declares ``file_size = 0`` while
    carrying a real ``compress_size`` and real data reads back as ``b""``
    through the ordinary API — even though ``java.util.zip.ZipFile``, which
    bounds a read by compressed size rather than by declared uncompressed
    size, returns the real bytes. Trivial to produce with ``ZIP_STORED``,
    which is exactly how Spring Boot packages nested JARs.

    Reads through a copy of ``info`` with ``file_size`` overridden to a
    sentinel large enough that it can never be the binding constraint, so
    the natural end of the compressed stream — not the declared size —
    decides where the read stops, the same bound a JVM uses. CRC-32
    validation is left untouched (the copy's ``CRC`` is not modified), so
    genuine data corruption — a truncated or flipped compressed stream that
    decompresses to something other than what was declared — still raises,
    exactly as with :func:`read_entry`. Goes through ``ZipFile.read`` (which
    accepts a ``ZipInfo`` in place of a name) rather than ``ZipFile.open``
    directly, so this is interchangeable with :func:`read_entry` from every
    caller's point of view — including a test that stubs ``ZipFile.read``
    to simulate a corrupt archive.
    """
    truthful = copy.copy(info)
    truthful.file_size = _UNBOUNDED_ENTRY_SIZE
    try:
        return archive.read(truthful)
    except READ_FAILURES as exc:
        raise MalformedArtifact(f"could not read {info.filename!r}: {exc}") from exc


def duplicate_entry_names(archive: zipfile.ZipFile) -> frozenset[str]:
    """Raw entry names that occur more than once in ``archive``'s central directory.

    ``zipfile.ZipFile.read(name)`` — and everything built on it that
    addresses an entry by its raw name string rather than by a specific
    ``ZipInfo`` — resolves a repeated raw name to whichever occurrence the
    central directory lists last; there is no public API to address an
    earlier one. Reading via the exact ``ZipInfo`` object a caller already
    holds from iterating ``infolist()`` (as :func:`read_entry_ignoring_declared_size`
    does) happens to reach the specific occurrence that object came from —
    but that is an implementation detail of this library, not a guarantee
    about which occurrence a JVM classloader would pick between two
    identically-named entries. That choice is implementation-defined
    regardless of what this process is able to read, so a caller with two
    identically-named entries has no trustworthy answer about which one
    matters, however it reads them.

    Callers pass this set to :func:`reject_duplicate_entry_name` immediately
    before reading an entry whose bytes will be used as evidence, so that
    case is refused outright rather than answered with an occurrence this
    process happened to pick.
    """
    counts = Counter(info.filename for info in archive.infolist())
    return frozenset(name for name, count in counts.items() if count > 1)


def reject_duplicate_entry_name(name: str, duplicate_names: frozenset[str]) -> None:
    """Raise MalformedArtifact if ``name`` names more than one entry in the archive.

    Call this immediately before reading an entry whose bytes will be used
    as evidence — hashed into a Library, or recursed into as a nested
    archive — never before a plain name COMPARISON: iterating every entry
    via ``infolist()`` and comparing names already sees every occurrence of
    a duplicated name, so a duplicate there cannot hide a match the way it
    can hide a read. See :func:`duplicate_entry_names`.
    """
    if name in duplicate_names:
        raise MalformedArtifact(
            f"duplicate archive entry {name!r}: which occurrence would be read is "
            "implementation-defined, so it cannot be used as evidence"
        )
