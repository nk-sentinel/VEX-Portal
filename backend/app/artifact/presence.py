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

import re
from collections.abc import Iterable

from app.artifact._archive import (
    Budget,
    enforce_limits,
    has_archive_suffix,
    open_zip,
    read_entry,
)
from app.artifact.errors import MalformedArtifact
from app.artifact.limits import DEFAULT_LIMITS, Limits

#: Public (not module-private) because app.artifact.inventory shares these —
#: previously each module carried its own copy, and independent copies drift:
#: presence.py's suffix test was lowercased and inventory.py's was not, which
#: made an uppercase-named bundled library visible to one check and invisible
#: to the other (see app.artifact._archive). One definition, imported, closes
#: that class of bug for the class/library prefixes too.
LAYOUT_CLASS_PREFIXES = ("BOOT-INF/classes/", "WEB-INF/classes/")
LIBRARY_DIR_PREFIXES = ("BOOT-INF/lib/", "WEB-INF/lib/")

#: Multi-release JARs place version-specific overrides under this prefix; such
#: a class loads on any Java 9+ JVM on a plain `java -jar`. Defined here (not
#: in app.artifact.inventory, which imports it) so there is exactly one
#: pattern for both the presence check and the inventory's class-admission
#: rule to share — two independently-written copies is how they drift.
MULTI_RELEASE_PREFIX = re.compile(r"^META-INF/versions/\d+/")

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
        budget=Budget(),
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
    prefix depending on how it was packaged, or under a multi-release
    override — a class there loads on any Java 9+ JVM just as its unversioned
    twin would, so a target must match a versioned copy exactly as it would
    match the unversioned one. The entry name has already been normalised by
    the caller (see :func:`normalize_entry_name`) — entry names are
    attacker-controlled, and canonicalising only the target would leave the
    naming evasion open.

    The two strips compose: applying each once against the ORIGINAL name
    only, independently of the other, matches neither pattern on
    ``META-INF/versions/9/BOOT-INF/classes/org/x/Y.class`` — a multi-release
    override of a layout-prefixed class. Spring Boot 3's nested ``JarFile``
    honours multi-release, so this is plausibly loadable. Both strips are
    therefore applied repeatedly, to every result produced so far, in either
    order, until neither pattern matches any remaining candidate — not just
    once each against the original string.
    """
    keys = {normalized_entry}
    frontier = {normalized_entry}
    while frontier:
        discovered: set[str] = set()
        for candidate in frontier:
            for prefix in LAYOUT_CLASS_PREFIXES:
                if candidate.startswith(prefix):
                    discovered.add(candidate.removeprefix(prefix))
            multi_release_stripped = MULTI_RELEASE_PREFIX.sub("", candidate)
            if multi_release_stripped != candidate:
                discovered.add(multi_release_stripped)
        frontier = discovered - keys
        keys |= discovered
    return tuple(keys)


def _in_library_directory(normalized_entry: str) -> bool:
    """Whether ``normalized_entry`` lives under a fat-JAR library directory.

    Spring Boot puts every bundled dependency under one of these prefixes as
    a non-directory entry on the classpath, regardless of what it is named —
    the framework's own loader does not check the extension, so neither can
    this. See :func:`_search`.
    """
    return any(normalized_entry.startswith(prefix) for prefix in LIBRARY_DIR_PREFIXES)


def _search(
    data: bytes,
    remaining: set[str],
    found: set[str],
    *,
    depth: int,
    max_depth: int,
    limits: Limits,
    budget: Budget,
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

    archive = open_zip(data)

    with archive:
        nested: list[str] = []
        for info in archive.infolist():
            enforce_limits(info, budget, limits)
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
            # Inside a library directory, every non-directory entry is a
            # classpath member regardless of name or extension — Spring Boot's
            # loader does not check either. Elsewhere, fall back to the
            # extension test. Both tests run against the normalised name, not
            # info.filename: a trailing-slash-with-content entry (see the
            # is_dir() comment above) would otherwise never match the suffix
            # test even though it carries a real nested archive's bytes.
            if _in_library_directory(entry) or has_archive_suffix(entry):
                nested.append(info.filename)
            if not remaining:
                return

        for name in nested:
            payload = read_entry(archive, name)
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
