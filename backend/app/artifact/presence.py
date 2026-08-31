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

:func:`collect_class_paths` is the one traversal implementation in this
module: it walks the archive once and resolves every target class path it is
given in that same walk. :func:`contains_class` is a convenience wrapper
around it for the single-target case; a caller checking many class paths
against one artifact — see :func:`app.evidence.pack.build_pack` — should call
:func:`collect_class_paths` directly rather than looping over
:func:`contains_class`, which would re-open and re-walk the archive per call.
"""

from __future__ import annotations

import io
import zipfile
import zlib
from collections.abc import Iterable
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

    One budget is created per top-level call into the walk (see
    :func:`collect_class_paths`) and threaded through every recursive
    descent into a nested archive, so the limits in :data:`Limits` bound the
    cost of one walk regardless of how many targets it is answering at once.
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


def collect_class_paths(
    data: bytes,
    targets: Iterable[str],
    *,
    max_depth: int = 3,
    limits: Limits = DEFAULT_LIMITS,
) -> set[str]:
    """Report which of ``targets`` are present, in a single walk of the artifact.

    This is the one traversal implementation the module has: it searches the
    application's own classes and recurses into bundled JARs once, checking
    every catalogued entry against every remaining target instead of
    re-opening and re-walking the archive per target. :func:`contains_class`
    is a one-element-set convenience wrapper around this function; a caller
    that has many class paths to resolve against the same artifact (see
    :func:`app.evidence.pack.build_pack`) should call this directly with all
    of them at once.

    Args:
        data: the artifact bytes.
        targets: the class paths to look for, in any of the forms
            :func:`normalize_class_path` accepts. Duplicates are fine.
        max_depth: how many levels of nested archive to descend. Spring Boot
            nests one level; shaded uber-JARs can nest deeper. The limit exists
            so a malicious or pathological archive cannot cause unbounded work.
        limits: resource bounds enforced while walking the archive. See
            :mod:`app.artifact.limits`.

    Returns:
        The subset of ``targets`` (as given, not normalised) found present.
        An empty result means none of them were found — Tier 1 proof for
        every target in the input, not just some of them, because the walk
        only stops short of visiting the whole reachable archive tree once
        every target has already been resolved.

    Raises:
        MalformedArtifact: the artifact or a nested archive could not be read,
            or nesting exceeded ``max_depth`` while targets remained
            unresolved. Never omits a target from the result silently for
            these reasons — see the module docstring.
        ArtifactTooLarge: the archive exceeded a resource bound before it
            could be searched exhaustively. Same rationale.
    """
    by_normalized: dict[str, list[str]] = {}
    for target in targets:
        by_normalized.setdefault(normalize_entry_name(target), []).append(target)
    if not by_normalized:
        return set()

    remaining = set(by_normalized)
    found_normalized: set[str] = set()
    _search(
        data,
        remaining,
        found_normalized,
        depth=0,
        max_depth=max_depth,
        limits=limits,
        budget=_Budget(),
    )

    found: set[str] = set()
    for key in found_normalized:
        found.update(by_normalized[key])
    return found


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
    :func:`candidate_class_paths`); every plausible form is tried in a single
    walk of the archive via :func:`collect_class_paths`, and absence is
    reported only once none of them was found.

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
    found = collect_class_paths(
        data, candidate_class_paths(class_path), max_depth=max_depth, limits=limits
    )
    return bool(found)


def _entry_match_keys(normalized_entry: str) -> tuple[str, ...]:
    """Every normalised target key that ``normalized_entry`` should satisfy.

    Callers pass the bare JVM name; the artifact may store it under a layout
    prefix depending on how it was packaged. The entry name has already been
    normalised by the caller (see :func:`normalize_entry_name`) — entry names
    are attacker-controlled, and canonicalising only the target would leave
    the naming evasion open.
    """
    keys = [normalized_entry]
    for prefix in _LAYOUT_CLASS_PREFIXES:
        if normalized_entry.startswith(prefix):
            keys.append(normalized_entry.removeprefix(prefix))
    return tuple(keys)


def _search(
    data: bytes,
    remaining: set[str],
    found: set[str],
    *,
    depth: int,
    max_depth: int,
    limits: Limits,
    budget: _Budget,
) -> None:
    """Walk ``data`` once, moving satisfied keys from ``remaining`` to ``found``.

    Recurses into every bundled JAR reachable within ``max_depth``, stopping
    early — at this level or a nested one — the moment ``remaining`` is empty,
    since there is nothing left to prove. Never returns while ``remaining`` is
    non-empty without having visited everything reachable within the depth
    budget: raising is always preferred to silently leaving a target
    unresolved.
    """
    if not remaining:
        return
    if depth >= max_depth:
        raise MalformedArtifact(
            f"archive nesting depth exceeded {max_depth} while looking for "
            f"{sorted(remaining)!r}; refusing to report absence without having "
            "searched exhaustively"
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
            # zipfile.ZipInfo.is_dir() is a bare name.endswith("/") test that
            # ignores file_size, so an entry named "…/Foo.class/" carrying real
            # content reads as a directory and would be skipped before its name is
            # ever compared. Treat anything with content as content: reporting a
            # present class as absent is Tier 1 proof that clears a finding.
            if info.is_dir() and info.file_size == 0:
                continue
            entry = normalize_entry_name(info.filename)
            for key in _entry_match_keys(entry):
                if key in remaining:
                    remaining.discard(key)
                    found.add(key)
            if info.filename.lower().endswith(_NESTED_ARCHIVE_SUFFIXES):
                nested.append(info.filename)
            if not remaining:
                return

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
                _search(
                    payload,
                    remaining,
                    found,
                    depth=depth + 1,
                    max_depth=max_depth,
                    limits=limits,
                    budget=budget,
                )
            except MalformedArtifact as exc:
                raise MalformedArtifact(f"while inspecting nested archive {name}: {exc}") from exc
            if not remaining:
                return
