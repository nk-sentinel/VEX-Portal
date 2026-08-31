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

from app.artifact._archive import Budget, enforce_limits, open_zip, read_entry
from app.artifact.errors import MalformedArtifact
from app.artifact.limits import DEFAULT_LIMITS, Limits
from app.artifact.presence import MULTI_RELEASE_PREFIX, normalize_entry_name


class Layout(Enum):
    """How an artifact separates application code from bundled dependencies."""

    SPRING_BOOT_FAT = "spring-boot-fat"  # BOOT-INF/classes + BOOT-INF/lib
    WAR = "war"                          # WEB-INF/classes  + WEB-INF/lib
    PLAIN_JAR = "plain-jar"              # classes at root, no bundled libraries


# (class prefix, library prefix) per layout.
_PREFIXES: dict[Layout, tuple[str, str]] = {
    Layout.SPRING_BOOT_FAT: ("BOOT-INF/classes/", "BOOT-INF/lib/"),
    Layout.WAR: ("WEB-INF/classes/", "WEB-INF/lib/"),
    Layout.PLAIN_JAR: ("", ""),
}

# Tooling shipped inside a Boot JAR that is not the application's own code.
_NON_APPLICATION_PREFIXES = ("org/springframework/boot/loader/", "META-INF/")

_COMMIT_KEYS = ("git.commit.id.full", "git.commit.id", "git.commit.id.abbrev")


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
    #: with the layout prefix stripped. Library classes are deliberately
    #: excluded: a library referencing a vulnerable class says nothing about
    #: whether the application does.
    app_classes: dict[str, bytes] = field(default_factory=dict)

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
        layout = _detect_layout(archive)
        class_prefix, library_prefix = _PREFIXES[layout]

        libraries: list[Library] = []
        app_classes: dict[str, bytes] = {}
        git_properties: dict[str, str] = {}
        git_properties_is_canonical = False
        budget = Budget()

        for info in archive.infolist():
            enforce_limits(info, budget, limits)
            # zipfile.ZipInfo.is_dir() is a bare name.endswith("/") test that
            # ignores file_size, so an entry named "…/Foo.class/" carrying real
            # content reads as a directory and would be skipped before its name is
            # ever compared. Treat anything with content as content: reporting a
            # present class as absent is Tier 1 proof that clears a finding.
            if info.is_dir() and info.file_size == 0:
                continue
            # Canonicalise once and use this form for every subsequent decision
            # (prefix tests, the app_classes key, the git.properties check).
            # Entry names are attacker-controlled — see app.artifact.presence —
            # and a raw-name comparison here is the same evasion one tier down:
            # a hidden class is dropped from app_classes, so its constant pool
            # is never scanned and it reads as unreferenced. `info.filename`
            # (the raw name) is kept only for archive.read(), which must
            # address the entry as the ZIP itself names it.
            name = normalize_entry_name(info.filename)

            if library_prefix and name.startswith(library_prefix):
                # Spring Boot puts every non-directory entry under the library
                # directory on the classpath regardless of extension — a
                # renamed or extensionless bundled dependency is not exempt
                # from the classpath, so it must not be exempt from provenance
                # hashing either. Filtering by ".jar" here left an entry like
                # "commons-text-1.9.zip" (or "EVIL.JAR", since this test used
                # to be case-sensitive) invisible to provenance while it was
                # still fully loadable by the JVM.
                payload = read_entry(archive, info.filename)
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
            elif name.endswith(".class") and _is_application_class(name, class_prefix, layout):
                key = name.removeprefix(class_prefix)
                if key in app_classes:
                    # Which entry a JVM's classloader picks between two
                    # identically-named entries is implementation-defined, so
                    # silently keeping "last wins" would report a scan of
                    # bytecode that might not be the bytecode that actually
                    # runs. That understates classes_scanned while still
                    # reporting the scan as conclusive.
                    raise MalformedArtifact(
                        f"duplicate application class entry {key!r}: which copy the JVM "
                        "would load is implementation-defined, so it cannot be scanned "
                        "exhaustively"
                    )
                app_classes[key] = read_entry(archive, info.filename)
            elif posixpath.basename(name) == "git.properties":
                # Prefer the application's own file at the canonical path. A fat
                # JAR can carry git.properties for bundled modules too, and
                # picking by archive order would make provenance depend on ZIP
                # layout rather than on the build.
                canonical = f"{class_prefix}git.properties" if class_prefix else "git.properties"
                if name == canonical:
                    git_properties = _parse_properties(read_entry(archive, info.filename))
                    git_properties_is_canonical = True
                elif not git_properties_is_canonical and not git_properties:
                    git_properties = _parse_properties(read_entry(archive, info.filename))

    libraries.sort(key=lambda library: library.path)
    return Inventory(
        layout=layout,
        libraries=libraries,
        app_classes=app_classes,
        git_properties=git_properties,
    )


def _detect_layout(archive: zipfile.ZipFile) -> Layout:
    """Infer layout from entry prefixes rather than the file extension.

    Spring Boot applications are frequently packaged as ``.war``, and a ``.war``
    built by other tooling is not a Boot application. The prefixes are reliable
    where the extension is not.
    """
    has_web_inf = False
    for info in archive.infolist():
        # A contentless directory entry ("BOOT-INF/classes/", zero bytes) is
        # inert to the JVM — it asserts nothing about the archive's layout.
        # Letting it decide layout would let one padding entry flip a plain
        # JAR to SPRING_BOOT_FAT, which then demands the BOOT-INF/classes/
        # prefix of every real class and empties app_classes entirely.
        if info.is_dir() and info.file_size == 0:
            continue
        name = normalize_entry_name(info.filename)
        if name.startswith("BOOT-INF/"):
            return Layout.SPRING_BOOT_FAT  # wins: a Boot fat WAR has both
        if name.startswith("WEB-INF/"):
            has_web_inf = True
    return Layout.WAR if has_web_inf else Layout.PLAIN_JAR


def _is_application_class(name: str, class_prefix: str, layout: Layout) -> bool:
    """Distinguish the application's own compiled code from everything else."""
    if layout is not Layout.PLAIN_JAR:
        return name.startswith(class_prefix)
    # Multi-release overrides live under META-INF/versions/<N>/ and ARE the
    # application's own bytecode. Strip that prefix and apply the ordinary
    # exclusion to the remainder, so a versioned copy of tooling is excluded
    # exactly as the unversioned copy is — admitting it would make the
    # reference scan report classes the application never touches.
    remainder = MULTI_RELEASE_PREFIX.sub("", name)
    return not remainder.startswith(_NON_APPLICATION_PREFIXES)


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
