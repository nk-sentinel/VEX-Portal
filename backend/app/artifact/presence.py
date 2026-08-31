"""Tier 1 proof: is the vulnerable class present in what actually ships.

Nexus IQ reports the implicated paths in ``rootCauses[].listOfPaths``, for
example ``org/apache/commons/text/StringSubstitutor.class``. If that class is
not in the artifact, it cannot execute, and the finding does not apply.

A ``False`` from :func:`contains_class` clears a finding. That is why every
failure path in this module raises instead of returning ``False``: a corrupt
archive, an unreadable nested JAR, or exceeded nesting depth are all "we do not
know", and reporting "we do not know" as "not present" would manufacture proof
out of a bug.

A ``True`` proves only presence, never use. Whether the application calls the
class is a Tier 2 question, answered in :mod:`app.artifact.references`.
"""

from __future__ import annotations

import io
import zipfile
import zlib
from dataclasses import dataclass

from app.artifact.errors import ArtifactTooLarge, MalformedArtifact
from app.artifact.limits import DEFAULT_LIMITS, Limits

_LAYOUT_CLASS_PREFIXES = ("BOOT-INF/classes/", "WEB-INF/classes/")
_NESTED_ARCHIVE_SUFFIXES = (".jar", ".war", ".ear")

#: Most nested-class nestings are shallow; this bounds candidate generation
#: for a dotted name without exploding combinatorially.
_MAX_NESTING_DEPTH = 3


def normalize_class_path(name: str) -> str:
    """Return the JVM internal form with a ``.class`` suffix.

    Accepts the forms a class is named in the wild: dotted
    (``com.example.Service``), JVM internal (``com/example/Service``), with or
    without the suffix.
    """
    stripped = name.strip()
    if stripped.endswith(".class"):
        return stripped
    if "/" not in stripped and "." in stripped:
        return stripped.replace(".", "/") + ".class"
    return stripped + ".class"


def candidate_class_paths(name: str) -> tuple[str, ...]:
    """Return every path a caller's class name might plausibly denote.

    A dotted name is ambiguous: ``com.example.Outer.Inner`` could be the class
    ``Inner`` in package ``com.example.Outer``, or the nested class
    ``Outer$Inner`` in package ``com.example``. Nothing in the string settles
    it. Rather than guess — and a wrong guess makes a present class look
    absent, which is Tier 1 proof that clears a finding — every plausible form
    is offered and the caller reports absence only if none of them is present.

    A name already in JVM internal form has exactly one candidate.
    """
    primary = normalize_class_path(name)
    stripped = name.strip()

    # Only a purely dotted name is ambiguous. Internal form is unambiguous.
    if "/" in stripped or stripped.endswith(".class"):
        return (primary,)

    segments = primary.removesuffix(".class").split("/")
    candidates = [primary]
    for nested in range(1, min(_MAX_NESTING_DEPTH, len(segments) - 1) + 1):
        package = segments[: len(segments) - nested - 1]
        classes = "$".join(segments[len(segments) - nested - 1 :])
        candidates.append("/".join([*package, classes]) + ".class")
    return tuple(dict.fromkeys(candidates))


def normalize_entry_name(name: str) -> str:
    """Reduce an archive entry name to a canonical comparable form.

    Archive entry names are attacker-controlled. ``./x``, ``a/../x``, ``\\x``
    and ``/x`` all name the same class to a JVM but compare unequal as strings,
    so a naive comparison lets a crafted name hide a class from the presence
    check — and a hidden class reads as Tier 1 proof that the vulnerability
    does not apply.
    """
    unified = name.replace("\\", "/")
    parts: list[str] = []
    for segment in unified.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        parts.append(segment)
    return "/".join(parts)


@dataclass(slots=True)
class _Budget:
    """Running totals for one archive walk, shared across nested recursion.

    A dotted class name can expand into several candidate paths, and each
    candidate re-walks the archive from scratch (see :func:`contains_class`),
    so a fresh budget is created per candidate rather than shared across all
    of them — otherwise an ordinary large artifact would be rejected purely
    because of how many candidates a caller's name happened to expand into.
    """

    entries: int = 0
    total_uncompressed: int = 0


def _enforce_limits(info: zipfile.ZipInfo, budget: _Budget, limits: Limits) -> None:
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


def contains_class(
    data: bytes,
    class_path: str,
    *,
    max_depth: int = 3,
    limits: Limits = DEFAULT_LIMITS,
) -> bool:
    """Report whether ``class_path`` is present anywhere in the artifact.

    Searches the application's own classes and recurses into bundled JARs,
    which is where the vulnerable class usually lives. A dotted ``class_path``
    is ambiguous between a top-level class and a nested class (see
    :func:`candidate_class_paths`); every plausible form is tried, and absence
    is reported only once none of them is present.

    Args:
        data: the artifact bytes.
        class_path: the class to look for, in any of the accepted forms.
        max_depth: how many levels of nested archive to descend. Spring Boot
            nests one level; shaded uber-JARs can nest deeper. The limit exists
            so a malicious or pathological archive cannot cause unbounded work.
        limits: resource bounds enforced while walking the archive. See
            :mod:`app.artifact.limits`.

    Raises:
        MalformedArtifact: the artifact or a nested archive could not be read,
            or nesting exceeded ``max_depth``. Never returns ``False`` for
            these — see the module docstring.
        ArtifactTooLarge: the archive exceeded a resource bound before it
            could be searched exhaustively. Never returns ``False`` for this,
            for the same reason.
    """
    for candidate in candidate_class_paths(class_path):
        if _search(data, candidate, depth=0, max_depth=max_depth, limits=limits, budget=_Budget()):
            return True
    return False


def _search(
    data: bytes,
    target: str,
    *,
    depth: int,
    max_depth: int,
    limits: Limits,
    budget: _Budget,
) -> bool:
    if depth >= max_depth:
        raise MalformedArtifact(
            f"archive nesting depth exceeded {max_depth} while looking for {target}; "
            "refusing to report absence without having searched exhaustively"
        )

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (
        zipfile.BadZipFile,
        zlib.error,
        OSError,
        RuntimeError,
        NotImplementedError,
        EOFError,
    ) as exc:
        raise MalformedArtifact(f"not a readable archive: {exc}") from exc

    with archive:
        nested: list[str] = []
        for info in archive.infolist():
            _enforce_limits(info, budget, limits)
            if info.is_dir():
                continue
            if _matches(info.filename, target):
                return True
            if info.filename.lower().endswith(_NESTED_ARCHIVE_SUFFIXES):
                nested.append(info.filename)

        for name in nested:
            try:
                payload = archive.read(name)
            except (
                zipfile.BadZipFile,
                zlib.error,
                OSError,
                RuntimeError,
                NotImplementedError,
                EOFError,
            ) as exc:
                raise MalformedArtifact(f"could not read nested archive {name}: {exc}") from exc
            try:
                if _search(
                    payload,
                    target,
                    depth=depth + 1,
                    max_depth=max_depth,
                    limits=limits,
                    budget=budget,
                ):
                    return True
            except MalformedArtifact as exc:
                raise MalformedArtifact(f"while inspecting nested archive {name}: {exc}") from exc

    return False


def _matches(entry: str, target: str) -> bool:
    """Compare an archive entry against the target, allowing layout prefixes.

    Callers pass the bare JVM name; the artifact may store it under a layout
    prefix depending on how it was packaged. Both sides are normalised before
    comparison: entry names are attacker-controlled, and canonicalising only
    the target would leave the naming evasion open.
    """
    entry = normalize_entry_name(entry)
    target = normalize_entry_name(target)
    if entry == target:
        return True
    return any(
        entry.removeprefix(prefix) == target
        for prefix in _LAYOUT_CLASS_PREFIXES
        if entry.startswith(prefix)
    )
