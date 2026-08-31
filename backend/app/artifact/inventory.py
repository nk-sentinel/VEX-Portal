"""JAR and WAR structure: what an artifact actually contains.

A dependency listed in a manifest is not the same as a class present in the
shipped artifact. Shading, minimization, ``<filters>`` and tree-shaking all
remove code the manifest still advertises, which is exactly the gap between
what a scanner reports and what actually ships.
"""

from __future__ import annotations

import hashlib
import posixpath
import zipfile
from dataclasses import dataclass, field
from enum import Enum

from app.artifact._archive import (
    Budget,
    duplicate_entry_names,
    enforce_limits,
    open_zip,
    read_entry,
    read_entry_ignoring_declared_size,
    reject_duplicate_entry_name,
)
from app.artifact.errors import MalformedArtifact
from app.artifact.limits import DEFAULT_LIMITS, Limits
from app.artifact.presence import (
    LAYOUT_CLASS_PREFIXES,
    LIBRARY_DIR_PREFIXES,
    MULTI_RELEASE_PREFIX,
    normalize_entry_name,
)


class Layout(Enum):
    """How an artifact separates application code from bundled dependencies.

    INFORMATIONAL ONLY. Earlier this module detected exactly one layout per
    artifact and let it gate what got collected — the class prefix and
    library prefix of the "winning" layout were the only ones ever examined.
    A single content-bearing decoy entry (a real, parseable class dropped at,
    say, BOOT-INF/classes/Decoy.class) then flipped detection and made every
    genuine class silently vanish from app_classes, because none of it
    carried the "winning" prefix. See :func:`inspect_archive`: collection now
    unions every known prefix regardless of which layout is detected, so
    this label may still be reported to a human reviewer but must never again
    be allowed to decide what gets scanned.
    """

    SPRING_BOOT_FAT = "spring-boot-fat"  # BOOT-INF/classes + BOOT-INF/lib
    WAR = "war"                          # WEB-INF/classes  + WEB-INF/lib
    PLAIN_JAR = "plain-jar"              # classes at root, no bundled libraries


#: The top-level namespace each known class/library prefix pair lives under,
#: derived from LAYOUT_CLASS_PREFIXES so it cannot drift out of sync with it.
#: A `.class` entry under one of these that is not under its recognised
#: classes/ or lib/ subdirectory matches no rule this module knows how to
#: interpret — see _application_class_key and Inventory.excluded_class_count.
_CONTAINER_PREFIXES = tuple(
    dict.fromkeys(prefix.split("/", 1)[0] + "/" for prefix in LAYOUT_CLASS_PREFIXES)
)

# Tooling shipped inside a Boot JAR that is not the application's own code.
_NON_APPLICATION_PREFIXES = ("org/springframework/boot/loader/", "META-INF/")

#: Every path at which a git.properties is treated as the application's own
#: build metadata rather than a bundled module's — one of the known class
#: directories, or the plain-JAR root. See the git.properties handling in
#: :func:`inspect_archive`.
_CANONICAL_GIT_PROPERTIES_PATHS = frozenset(
    {f"{prefix}git.properties" for prefix in LAYOUT_CLASS_PREFIXES} | {"git.properties"}
)

_COMMIT_KEYS = ("git.commit.id.full", "git.commit.id", "git.commit.id.abbrev")


class _Exclusion(Enum):
    """Why a `.class` entry was not admitted to Inventory.app_classes."""

    #: Recognised non-application content — a Boot loader class, or ordinary
    #: META-INF/ content — that ships inside every artifact of this kind and
    #: is deliberately excluded. Admitting it would make the reference scan
    #: report classes the application never touches. Not counted against
    #: Inventory.excluded_class_count: this is an expected, understood
    #: exclusion, not evidence of a gap in this module's coverage.
    TOOLING = "tooling"

    #: A `.class` entry inside a namespace this module recognises as a
    #: packaging container (BOOT-INF/, WEB-INF/) but not under either
    #: subdirectory of it this module knows how to interpret. Counted
    #: against Inventory.excluded_class_count: some packaging convention
    #: this module has not been taught about could be putting real
    #: application code here, and scanning a subset of the application's
    #: classes is not evidence about the ones skipped.
    UNRECOGNISED = "unrecognised"


@dataclass(frozen=True, slots=True)
class Library:
    """A JAR bundled inside the artifact — a component a scanner would identify."""

    path: str
    name: str
    sha1: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class Inventory:
    """Everything the artifact actually contains."""

    layout: Layout
    libraries: list[Library] = field(default_factory=list)

    #: Application's own compiled classes, keyed by path in JVM internal form
    #: with the matched layout prefix stripped (or the entry's own path, for
    #: a class admitted by the plain-JAR root rule). Collected as a UNION
    #: over every known class prefix plus the root rule — never gated by
    #: which single layout was detected; see Layout and inspect_archive.
    #: When two different prefixes strip to the same key, that is the
    #: duplicate-entry case: identical content is deduplicated, differing
    #: content raises MalformedArtifact, because which copy a JVM would load
    #: is implementation-defined. Library classes are deliberately excluded:
    #: a library referencing a vulnerable class says nothing about whether
    #: the application does.
    app_classes: dict[str, bytes] = field(default_factory=dict)

    #: Count of `.class` entries present in the archive that were excluded
    #: from app_classes for a reason OTHER than the recognised tooling
    #: exclusions — see _Exclusion.UNRECOGNISED. Zero means every class this
    #: module could not positively identify as tooling was collected.
    #: Non-zero means some class went unscanned for a reason this module
    #: cannot explain, so app.artifact.references.scan_references must not
    #: report the resulting scan as conclusive: scanning a subset of the
    #: application's classes is not evidence about the ones skipped.
    excluded_class_count: int = 0

    git_properties: dict[str, str] = field(default_factory=dict)

    def commit_sha(self) -> str | None:
        """The git commit recorded inside the artifact, if the build embedded one.

        This is the strongest self-contained provenance signal available: the
        identifier travels inside the artifact being analysed, so it cannot
        drift the way a branch pointer or an external property can.
        """
        for key in _COMMIT_KEYS:
            value = self.git_properties.get(key)
            if value:
                return value
        return None

    def repository_url(self) -> str | None:
        """The git remote recorded inside the artifact, if present."""
        return self.git_properties.get("git.remote.origin.url") or None

    def library_sha1s(self) -> dict[str, str]:
        """Bundled library hashes mapped to names, for provenance comparison."""
        return {library.sha1: library.name for library in self.libraries}


def inspect_archive(data: bytes, *, limits: Limits = DEFAULT_LIMITS) -> Inventory:
    """Read a JAR or WAR and report what it contains.

    Args:
        data: the artifact bytes.
        limits: resource bounds enforced while walking the archive. See
            :mod:`app.artifact.limits`.

    Raises:
        MalformedArtifact: the bytes are not a readable ZIP archive, or an
            entry inside it could not be read.
        ArtifactTooLarge: the archive exceeded a resource bound before it
            could be read exhaustively.
    """
    archive = open_zip(data)

    with archive:
        # `layout` is reported on the returned Inventory for a human
        # reviewer, but — unlike before — nothing below uses it to decide
        # what gets collected. Collection unions every known class/library
        # prefix instead of picking the single prefix pair belonging to
        # whichever layout was detected. A single content-bearing decoy
        # entry (a real, parseable class at, say, BOOT-INF/classes/Decoy)
        # used to be able to flip layout and, with it, silently empty
        # app_classes of every genuine class packaged under the OTHER
        # prefix — see the Layout docstring.
        layout = _detect_layout(archive)

        libraries: list[Library] = []
        app_classes: dict[str, bytes] = {}
        # The raw (pre-normalisation) entry name that supplied the current
        # app_classes[key] payload — see the duplicate-handling comment below.
        app_class_sources: dict[str, str] = {}
        excluded_class_count = 0
        git_properties: dict[str, str] = {}
        git_properties_is_canonical = False
        budget = Budget()
        # See reject_duplicate_entry_name below: a raw name the ZIP central
        # directory lists twice has no trustworthy read, by name or by
        # ZipInfo object, because we cannot know which occurrence a JVM
        # would resolve to. Computed once per archive, not per entry.
        duplicate_names = duplicate_entry_names(archive)

        for info in archive.infolist():
            enforce_limits(info, budget, limits)
            # zipfile.ZipInfo.is_dir() is a bare name.endswith("/") test that
            # ignores both size fields, so an entry named "…/Foo.class/"
            # carrying real content reads as a directory and would be
            # skipped before its name is ever compared. Treat anything with
            # content as content: reporting a present class as absent is
            # Tier 1 proof that clears a finding. Both declared sizes must be
            # zero, not just file_size: file_size is attacker-controlled
            # central-directory metadata (see read_entry_ignoring_declared_size
            # in app.artifact._archive), but an entry with compress_size == 0
            # truly has no data for any reader, Python or JVM — that is what
            # actually proves emptiness.
            if info.is_dir() and info.file_size == 0 and info.compress_size == 0:
                continue
            # Canonicalise once and use this form for every subsequent decision
            # (prefix tests, the app_classes key, the git.properties check).
            # Entry names are attacker-controlled — see app.artifact.presence —
            # and a raw-name comparison here is the same evasion one tier down:
            # a hidden class is dropped from app_classes, so its constant pool
            # is never scanned and it reads as unreferenced. `info` itself
            # (carrying the raw name) is kept only for reading the entry,
            # which must address it as the ZIP itself names it.
            name = normalize_entry_name(info.filename)

            library_prefix = next(
                (prefix for prefix in LIBRARY_DIR_PREFIXES if name.startswith(prefix)), None
            )
            if library_prefix is not None:
                # Spring Boot puts every non-directory entry under the library
                # directory on the classpath regardless of extension — a
                # renamed or extensionless bundled dependency is not exempt
                # from the classpath, so it must not be exempt from provenance
                # hashing either. Filtering by ".jar" here left an entry like
                # "commons-text-1.9.zip" (or "EVIL.JAR", since this test used
                # to be case-sensitive) invisible to provenance while it was
                # still fully loadable by the JVM. Every known library prefix
                # is tried, not just the one belonging to the detected layout
                # — see inspect_archive's opening comment. Read the way a JVM
                # does — bounded by compressed size, not the declared
                # (attacker-controlled) uncompressed size — so a library that
                # declares file_size = 0 to hide from provenance hashing
                # while shipping real, fully loadable bytes is hashed from
                # its true content instead of from a truncated empty read.
                # See read_entry_ignoring_declared_size and the N1 fix.
                #
                # N3: a raw name the central directory lists twice cannot be
                # read trustworthily even via the ZipInfo object above —
                # that only fixes which occurrence THIS process reads, not
                # which one a JVM classloader would. Refuse before reading
                # rather than silently hash an occurrence we picked.
                reject_duplicate_entry_name(info.filename, duplicate_names)
                payload = read_entry_ignoring_declared_size(archive, info)
                libraries.append(
                    Library(
                        path=name,
                        name=posixpath.basename(name),
                        # SHA-1 is not a free choice: Nexus IQ publishes component
                        # hashes in this format, so provenance matching must be
                        # like-for-like. usedforsecurity=False asserts only that
                        # this digest need not be available under FIPS policy — it
                        # is not a claim that collision resistance is irrelevant
                        # here. SHA-256 is carried alongside for consumers that can
                        # compare it.
                        sha1=hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
                        sha256=hashlib.sha256(payload).hexdigest(),
                        size=len(payload),
                    )
                )
            elif name.endswith(".class"):
                outcome = _application_class_key(name)
                if isinstance(outcome, str):
                    key = outcome
                    if app_class_sources.get(key) == info.filename:
                        # The exact same raw entry name recurs in the ZIP
                        # directory (e.g. two zf.writestr() calls with an
                        # identical name). zipfile.ZipFile.read() addresses
                        # entries BY NAME, resolving to whichever occurrence
                        # was registered last regardless of which one this
                        # loop is currently visiting — so a content
                        # comparison here would not be trustworthy; it could
                        # compare the later entry's bytes against themselves
                        # and wrongly conclude "identical". Which copy a
                        # JVM's classloader would load between two
                        # identically-named entries is implementation-defined
                        # regardless, so this always raises.
                        raise MalformedArtifact(
                            f"duplicate application class entry {info.filename!r}: which "
                            "copy the JVM would load is implementation-defined, so it "
                            "cannot be scanned exhaustively"
                        )
                    # Same reasoning as the library read above: file_size is
                    # attacker-controlled central-directory metadata, and an
                    # entry declaring file_size = 0 (a trailing-slash name
                    # like "…/Hidden.class/" that also passed the is_dir()
                    # guard above because compress_size is nonzero, or a
                    # plainly-named entry lying the same way) would otherwise
                    # be admitted to app_classes with a truncated, empty
                    # payload — collected in name only, with nothing left for
                    # the reference scan to examine. See
                    # read_entry_ignoring_declared_size.
                    payload = read_entry_ignoring_declared_size(archive, info)
                    existing = app_classes.get(key)
                    if existing is not None and existing != payload:
                        # Two different prefixes stripped to the same key
                        # with DIFFERENT content — the raw names differ (the
                        # branch above did not fire), so this read is
                        # trustworthy. Which copy a JVM's classloader would
                        # pick between them is still implementation-defined,
                        # so this raises too. Identical content is
                        # deduplicated without raising: see below.
                        raise MalformedArtifact(
                            f"duplicate application class entry {key!r}: two different "
                            "archive entries resolve to the same application class path "
                            "with different content; which copy the JVM would load is "
                            "implementation-defined, so it cannot be scanned exhaustively"
                        )
                    app_classes[key] = payload
                    app_class_sources[key] = info.filename
                elif outcome is _Exclusion.UNRECOGNISED:
                    excluded_class_count += 1
                # else: _Exclusion.TOOLING — recognised non-application
                # content, not the application's own code and not evidence
                # of a coverage gap either.
            elif posixpath.basename(name) == "git.properties":
                # Prefer the application's own file at a canonical path. A fat
                # JAR can carry git.properties for bundled modules too, and
                # picking by archive order would make provenance depend on ZIP
                # layout rather than on the build. Every known canonical path
                # is accepted, not just the one for the detected layout.
                if name in _CANONICAL_GIT_PROPERTIES_PATHS:
                    git_properties = _parse_properties(read_entry(archive, info.filename))
                    git_properties_is_canonical = True
                elif not git_properties_is_canonical and not git_properties:
                    git_properties = _parse_properties(read_entry(archive, info.filename))

    libraries.sort(key=lambda library: library.path)
    return Inventory(
        layout=layout,
        libraries=libraries,
        app_classes=app_classes,
        excluded_class_count=excluded_class_count,
        git_properties=git_properties,
    )


def _detect_layout(archive: zipfile.ZipFile) -> Layout:
    """Infer layout from entry prefixes rather than the file extension, for reporting only.

    Spring Boot applications are frequently packaged as ``.war``, and a ``.war``
    built by other tooling is not a Boot application. The prefixes are reliable
    where the extension is not. This label is INFORMATIONAL — see the Layout
    docstring — so getting it wrong on some exotic archive no longer risks
    dropping real application code; the zero-byte carve-out below is kept
    because a padding directory entry genuinely says nothing about how an
    artifact is packaged, not because a wrong answer here would be unsafe.
    """
    has_web_inf = False
    for info in archive.infolist():
        # A contentless directory entry ("BOOT-INF/classes/", zero bytes) is
        # inert to the JVM — it asserts nothing about the archive's layout.
        if info.is_dir() and info.file_size == 0:
            continue
        name = normalize_entry_name(info.filename)
        if name.startswith("BOOT-INF/"):
            return Layout.SPRING_BOOT_FAT  # wins: a Boot fat WAR has both
        if name.startswith("WEB-INF/"):
            has_web_inf = True
    return Layout.WAR if has_web_inf else Layout.PLAIN_JAR


def _application_class_key(name: str) -> str | _Exclusion:
    """Classify a normalised entry name ending in ``.class``.

    Returns the key to store it under in ``Inventory.app_classes`` if it is
    the application's own code, or the :class:`_Exclusion` reason it is not.
    Tries every known class prefix in turn — not just one tied to a single
    detected layout — so a decoy packaged under one prefix can never cause
    real code packaged under another to be dropped; see :func:`inspect_archive`.
    """
    for prefix in LAYOUT_CLASS_PREFIXES:
        if name.startswith(prefix):
            return name.removeprefix(prefix)
    if name.startswith(_CONTAINER_PREFIXES):
        # Inside a namespace this module recognises as a packaging container
        # (BOOT-INF/, WEB-INF/) but not under the classes/ or lib/
        # subdirectory it knows how to interpret there. Neither the class
        # prefix rule above nor the library prefix check (run before this
        # function is ever called) matched, so this is not tooling — it is a
        # gap in what this module has been taught to recognise.
        return _Exclusion.UNRECOGNISED
    # Plain-JAR root rule: everything left is a class outside any known
    # container, admitted at its own path. Multi-release overrides live
    # under META-INF/versions/<N>/ and ARE the application's own bytecode.
    # Strip that prefix and apply the ordinary exclusion to the remainder, so
    # a versioned copy of tooling is excluded exactly as the unversioned
    # copy is — admitting it would make the reference scan report classes
    # the application never touches.
    remainder = MULTI_RELEASE_PREFIX.sub("", name)
    if remainder.startswith(_NON_APPLICATION_PREFIXES):
        return _Exclusion.TOOLING
    return name


def _parse_properties(raw: bytes) -> dict[str, str]:
    """Parse a java.util.Properties file.

    Covers what the build plugins emit for git.properties and
    build-info.properties: ``key=value`` or ``key:value``, ``#`` and ``!``
    comments. Line continuations and unicode escapes are not supported because
    those plugins do not produce them.
    """
    properties: dict[str, str] = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        separator = min(
            (i for i in (stripped.find("="), stripped.find(":")) if i >= 0), default=-1
        )
        if separator < 0:
            continue
        key = stripped[:separator].strip()
        value = stripped[separator + 1 :].strip()
        for escaped, literal in ((r"\:", ":"), (r"\=", "="), ("\\\\", "\\")):
            value = value.replace(escaped, literal)
        properties[key] = value
    return properties
