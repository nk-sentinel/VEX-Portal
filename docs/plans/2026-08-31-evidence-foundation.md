# Evidence Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the offline evidence engine that determines what a built artifact actually contains and whether it matches the scan report it claims to come from — the Tier 1 and Tier 2 evidence on which every determination rests.

**Architecture:** Pure functions over byte streams, no I/O and no database. A JAR is a ZIP, a container image is a stack of TARs, and a Java class file is a parseable binary with a constant pool listing every class it references. Everything here is deterministic and testable against synthetic fixtures constructed in the tests themselves, so the whole plan is buildable with no access to Nexus IQ, JFrog, or Bitbucket.

**Tech Stack:** Python 3.12, standard library only (`zipfile`, `tarfile`, `gzip`, `struct`, `hashlib`), pytest.

**Spec:** `docs/design.md` — see "Deterministic decision tiers" and "Provenance". Terminology rules in `docs/naming.md`.

## Global Constraints

- Python `>=3.12`. Dependency versions are **pinned, never floated** (`backend/pyproject.toml`).
- **This plan adds no third-party dependencies.** Standard library only. If you reach for one, you have taken a wrong turn.
- **Never use the word "waiver"** in any identifier, docstring, log message, or error string. The vocabulary is *determination*, *assessment*, *Not Affected*. See `docs/naming.md`.
- **Tier 3 signals may never clear a finding.** Nothing in this plan produces a Tier 3 signal, but do not add one.
- **A parse failure must never be reported as absence.** "The class is not in the artifact" is Tier 1 proof; "I could not read the artifact" is an error. Conflating them manufactures proof out of a bug. Every function here raises on malformed input rather than returning a negative result.
- Lint and type gates: `ruff check app tests` and `mypy app` (strict) must pass before each commit.
- Test discipline: `filterwarnings = ["error::DeprecationWarning", ...]` is set in `pyproject.toml`. Warnings fail the suite.
- Run tests with `cd backend && PYTHONPATH=. .venv/bin/pytest`.

---

## File Structure

| File | Responsibility |
|---|---|
| `backend/app/artifact/__init__.py` | Package marker; re-exports the public surface |
| `backend/app/artifact/errors.py` | Exception hierarchy shared by all artifact code |
| `backend/app/artifact/inventory.py` | JAR/WAR structure: layout, bundled libraries, app classes, embedded git metadata |
| `backend/app/artifact/presence.py` | Tier 1: is a given class present anywhere in the artifact |
| `backend/app/artifact/classfile.py` | Java class file constant-pool parsing |
| `backend/app/artifact/references.py` | Tier 2: every class referenced by the application's own bytecode |
| `backend/app/artifact/image.py` | Container image layer walking, locating the application archive |
| `backend/app/provenance/__init__.py` | Package marker |
| `backend/app/provenance/fingerprint.py` | Dependency-set match between report components and artifact libraries |
| `backend/app/evidence/__init__.py` | Package marker |
| `backend/app/evidence/pack.py` | Assembles collected facts into the structure the rule engine consumes |
| `backend/app/artifact/cli.py` | Smoke tool: inspect a real artifact from the command line |
| `backend/tests/artifact/factories.py` | Builders for synthetic JARs, class files, and image layers |

Split by responsibility rather than by layer: `presence.py` and `references.py` are separate because they answer different questions with different evidential weight — presence is proof, references are defeasible. Keeping them apart stops a future edit from quietly letting one borrow the other's confidence.

---

### Task 1: Test factories for synthetic artifacts

Everything downstream needs JARs and class files to test against. Building them in code rather than committing binary fixtures keeps the tests readable and lets each test state exactly the structure it depends on.

**Files:**
- Create: `backend/app/artifact/__init__.py`
- Create: `backend/app/artifact/errors.py`
- Create: `backend/tests/artifact/__init__.py`
- Create: `backend/tests/artifact/factories.py`
- Test: `backend/tests/artifact/test_factories.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `make_class_file(class_names: list[str], *, with_long_entry: bool = False) -> bytes`
  - `make_jar(entries: dict[str, bytes]) -> bytes`
  - `make_spring_boot_jar(app_classes: dict[str, bytes], libraries: dict[str, bytes], git_properties: dict[str, str] | None = None) -> bytes`
  - `errors.ArtifactError`, `errors.MalformedArtifact`, `errors.NotAClassFile`

- [ ] **Step 1: Write the exception hierarchy**

`backend/app/artifact/errors.py`:

```python
"""Failures raised while inspecting artifacts.

These exist so that "I could not read this" is never silently reported as
"the class is not present". The first is a bug or a corrupt input; the second
is Tier 1 proof that clears a finding. Collapsing them would manufacture proof
out of a parse failure.
"""


class ArtifactError(Exception):
    """Base for every failure raised while inspecting an artifact."""


class MalformedArtifact(ArtifactError):
    """The artifact could not be read as the archive type it claims to be."""


class NotAClassFile(ArtifactError):
    """The bytes given are not a Java class file."""


class MalformedClassFile(ArtifactError):
    """The class file header parsed but its constant pool did not."""
```

Create `backend/app/artifact/__init__.py` as an empty file for now, and
`backend/tests/artifact/__init__.py` as an empty file.

- [ ] **Step 2: Write the failing test for the class file factory**

`backend/tests/artifact/test_factories.py`:

```python
import struct

from tests.artifact.factories import make_class_file, make_jar, make_spring_boot_jar


def test_class_file_has_java_magic_number():
    data = make_class_file(["com/example/Service"])
    assert data[:4] == b"\xca\xfe\xba\xbe"


def test_class_file_declares_pool_count_covering_every_entry():
    # Two entries per class name: one Utf8 holding the name, one Class
    # pointing at it. constant_pool_count is the highest index plus one.
    data = make_class_file(["com/example/A", "com/example/B"])
    pool_count = struct.unpack_from(">H", data, 8)[0]
    assert pool_count == 5


def test_long_entry_consumes_two_pool_slots():
    # CONSTANT_Long and CONSTANT_Double occupy two constant pool indices each
    # despite being one physical entry. This is the classic parser bug, so the
    # factory must be able to produce the shape that triggers it.
    data = make_class_file(["com/example/A"], with_long_entry=True)
    pool_count = struct.unpack_from(">H", data, 8)[0]
    assert pool_count == 4


def test_make_jar_round_trips_entries():
    import io
    import zipfile

    raw = make_jar({"com/example/Service.class": b"payload"})
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        assert zf.read("com/example/Service.class") == b"payload"


def test_spring_boot_jar_places_entries_under_boot_inf():
    import io
    import zipfile

    raw = make_spring_boot_jar(
        app_classes={"com/example/App.class": b"x"},
        libraries={"commons-text-1.9.jar": make_jar({})},
        git_properties={"git.commit.id.full": "4a9f1c2"},
    )
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        names = set(zf.namelist())
    assert "BOOT-INF/classes/com/example/App.class" in names
    assert "BOOT-INF/lib/commons-text-1.9.jar" in names
    assert "BOOT-INF/classes/git.properties" in names
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/artifact/test_factories.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tests.artifact.factories'`

- [ ] **Step 4: Write the factories**

`backend/tests/artifact/factories.py`:

```python
"""Builders for synthetic artifacts.

Tests construct the exact structure they depend on rather than relying on
committed binary fixtures, so a test's preconditions are readable in the test.
"""

from __future__ import annotations

import io
import struct
import zipfile

# Java class file constants
_MAGIC = 0xCAFEBABE
_MAJOR_JAVA_8 = 52

_TAG_UTF8 = 1
_TAG_LONG = 5
_TAG_CLASS = 7


def make_class_file(class_names: list[str], *, with_long_entry: bool = False) -> bytes:
    """Build a minimal but structurally valid Java class file.

    Each name in ``class_names`` produces a CONSTANT_Utf8 entry holding the
    name and a CONSTANT_Class entry pointing at it, which is what a real
    compiler emits for every class the code references.

    ``with_long_entry`` prepends a CONSTANT_Long. Long and Double each occupy
    *two* constant pool indices despite being a single physical entry; a parser
    that increments by one desynchronises for the rest of the pool. The factory
    can produce that shape so the parser can be tested against it.
    """
    pool = bytearray()
    count = 0

    def add(raw: bytes) -> int:
        nonlocal count
        pool.extend(raw)
        count += 1
        return count

    if with_long_entry:
        pool.extend(struct.pack(">B", _TAG_LONG) + b"\x00" * 8)
        count += 2  # occupies two indices

    for name in class_names:
        encoded = name.encode("utf-8")
        name_index = add(struct.pack(">BH", _TAG_UTF8, len(encoded)) + encoded)
        add(struct.pack(">BH", _TAG_CLASS, name_index))

    header = struct.pack(">IHHH", _MAGIC, 0, _MAJOR_JAVA_8, count + 1)
    # access_flags, this_class, super_class, and four zero counts. Nothing
    # downstream reads past the constant pool, so these need only be present.
    trailer = struct.pack(">HHHHHHH", 0x0021, 0, 0, 0, 0, 0, 0)
    return header + bytes(pool) + trailer


def make_jar(entries: dict[str, bytes]) -> bytes:
    """Build a JAR (a ZIP) containing exactly ``entries``."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    return buffer.getvalue()


def make_spring_boot_jar(
    app_classes: dict[str, bytes],
    libraries: dict[str, bytes],
    git_properties: dict[str, str] | None = None,
) -> bytes:
    """Build a Spring Boot fat JAR: app code under BOOT-INF/classes, bundled
    dependencies under BOOT-INF/lib."""
    entries: dict[str, bytes] = {}
    for name, payload in app_classes.items():
        entries[f"BOOT-INF/classes/{name}"] = payload
    for name, payload in libraries.items():
        entries[f"BOOT-INF/lib/{name}"] = payload
    if git_properties is not None:
        rendered = "".join(f"{k}={v}\n" for k, v in git_properties.items())
        entries["BOOT-INF/classes/git.properties"] = rendered.encode("utf-8")
    return make_jar(entries)


def make_war(
    app_classes: dict[str, bytes], libraries: dict[str, bytes]
) -> bytes:
    """Build a WAR: app code under WEB-INF/classes, dependencies under WEB-INF/lib."""
    entries: dict[str, bytes] = {}
    for name, payload in app_classes.items():
        entries[f"WEB-INF/classes/{name}"] = payload
    for name, payload in libraries.items():
        entries[f"WEB-INF/lib/{name}"] = payload
    return make_jar(entries)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/artifact/test_factories.py -v`
Expected: PASS — 5 tests

- [ ] **Step 6: Commit**

```bash
cd backend
git add app/artifact/__init__.py app/artifact/errors.py tests/artifact/
git commit -m "Add artifact error hierarchy and synthetic test factories

The error types exist to keep 'could not read this' distinct from 'the class
is absent'. The first is a bug; the second is Tier 1 proof that clears a
finding. Collapsing them would manufacture proof out of a parse failure."
```

---

### Task 2: Java class file constant-pool parser

Every class a compiled class references appears in its constant pool. This is the basis of Tier 2 evidence, and it is stronger than source grep because it reflects what the compiler actually emitted.

**Files:**
- Create: `backend/app/artifact/classfile.py`
- Test: `backend/tests/artifact/test_classfile.py`

**Interfaces:**
- Consumes: `errors.NotAClassFile`, `errors.MalformedClassFile` (Task 1); `make_class_file` (Task 1)
- Produces: `referenced_classes(data: bytes) -> set[str]` — returns JVM internal names without the `.class` suffix, e.g. `{"com/example/Service"}`

- [ ] **Step 1: Write the failing test**

`backend/tests/artifact/test_classfile.py`:

```python
import pytest

from app.artifact.classfile import referenced_classes
from app.artifact.errors import MalformedClassFile, NotAClassFile
from tests.artifact.factories import make_class_file


def test_extracts_referenced_class_names():
    data = make_class_file(["com/example/Service", "org/apache/commons/text/StringSubstitutor"])
    assert referenced_classes(data) == {
        "com/example/Service",
        "org/apache/commons/text/StringSubstitutor",
    }


def test_returns_empty_set_when_nothing_referenced():
    assert referenced_classes(make_class_file([])) == set()


def test_long_entry_does_not_desynchronise_the_pool():
    # CONSTANT_Long occupies two pool indices. A parser that advances by one
    # reads the following entry at the wrong offset and either crashes or
    # silently returns wrong names — which, for a Tier 2 check, means wrongly
    # concluding a vulnerable class is unreferenced.
    data = make_class_file(["com/example/Service"], with_long_entry=True)
    assert referenced_classes(data) == {"com/example/Service"}


def test_rejects_input_that_is_not_a_class_file():
    with pytest.raises(NotAClassFile):
        referenced_classes(b"PK\x03\x04 this is a zip")


def test_rejects_truncated_input():
    with pytest.raises(NotAClassFile):
        referenced_classes(b"\xca\xfe")


def test_rejects_unknown_constant_pool_tag():
    # An unrecognised tag means the parser cannot know the entry's width and
    # therefore cannot trust anything after it. Raising is mandatory: returning
    # a partial set here would understate the references and could clear a
    # finding that should not be cleared.
    data = bytearray(make_class_file(["com/example/Service"]))
    data[10] = 99  # first pool entry's tag
    with pytest.raises(MalformedClassFile):
        referenced_classes(bytes(data))
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/artifact/test_classfile.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.artifact.classfile'`

- [ ] **Step 3: Write the parser**

`backend/app/artifact/classfile.py`:

```python
"""Java class file constant-pool parsing.

Every class referenced by a compiled class appears in that class's constant
pool as a CONSTANT_Class entry. Reading them gives compiled-reality evidence of
what the code actually touches — stronger than searching source, because it
survives formatting, aliasing, and star imports.

It is still defeasible: reflection, ServiceLoader, and dependency injection all
reach classes that never appear in a constant pool. That is why this produces
Tier 2 evidence rather than Tier 1 proof, and why the anti-check for dynamic
dispatch is mandatory before acting on it.

Format reference: JVMS §4.4.
"""

from __future__ import annotations

import struct

from app.artifact.errors import MalformedClassFile, NotAClassFile

_MAGIC = b"\xca\xfe\xba\xbe"

_TAG_UTF8 = 1
_TAG_LONG = 5
_TAG_DOUBLE = 6
_TAG_CLASS = 7

# Byte width of each constant pool entry's payload, excluding the tag byte.
# Utf8 is absent because its width is length-prefixed and read separately.
_PAYLOAD_WIDTH: dict[int, int] = {
    3: 4,   # Integer
    4: 4,   # Float
    5: 8,   # Long
    6: 8,   # Double
    7: 2,   # Class
    8: 2,   # String
    9: 4,   # Fieldref
    10: 4,  # Methodref
    11: 4,  # InterfaceMethodref
    12: 4,  # NameAndType
    15: 3,  # MethodHandle
    16: 2,  # MethodType
    17: 4,  # Dynamic
    18: 4,  # InvokeDynamic
    19: 2,  # Module
    20: 2,  # Package
}

# Long and Double each take two constant pool indices despite being one entry.
_DOUBLE_WIDTH_TAGS = frozenset({_TAG_LONG, _TAG_DOUBLE})

_HEADER_SIZE = 10  # magic(4) + minor(2) + major(2) + constant_pool_count(2)


def referenced_classes(data: bytes) -> set[str]:
    """Return every class name referenced in ``data``'s constant pool.

    Names are JVM internal form without the ``.class`` suffix, for example
    ``org/apache/commons/text/StringSubstitutor``.

    Raises:
        NotAClassFile: the bytes are not a class file, or are truncated.
        MalformedClassFile: the header parsed but the constant pool did not.
    """
    if len(data) < _HEADER_SIZE:
        raise NotAClassFile(f"input is {len(data)} bytes, too short to be a class file")
    if data[:4] != _MAGIC:
        raise NotAClassFile("input does not begin with the Java class file magic number")

    pool_count = struct.unpack_from(">H", data, 8)[0]
    offset = _HEADER_SIZE

    utf8_by_index: dict[int, str] = {}
    class_name_indexes: list[int] = []

    index = 1
    while index < pool_count:
        if offset >= len(data):
            raise MalformedClassFile(
                f"constant pool ended at index {index} of {pool_count - 1}: input truncated"
            )
        tag = data[offset]
        offset += 1

        if tag == _TAG_UTF8:
            if offset + 2 > len(data):
                raise MalformedClassFile(f"truncated Utf8 length at pool index {index}")
            length = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            if offset + length > len(data):
                raise MalformedClassFile(f"truncated Utf8 payload at pool index {index}")
            utf8_by_index[index] = data[offset : offset + length].decode("utf-8", "replace")
            offset += length
        else:
            width = _PAYLOAD_WIDTH.get(tag)
            if width is None:
                # Without the width we cannot find the next entry, so nothing
                # after this point can be trusted. Returning what we have would
                # understate the references and could wrongly clear a finding.
                raise MalformedClassFile(
                    f"unknown constant pool tag {tag} at index {index}; cannot determine entry width"
                )
            if offset + width > len(data):
                raise MalformedClassFile(f"truncated entry (tag {tag}) at pool index {index}")
            if tag == _TAG_CLASS:
                class_name_indexes.append(struct.unpack_from(">H", data, offset)[0])
            offset += width

        index += 2 if tag in _DOUBLE_WIDTH_TAGS else 1

    return {
        utf8_by_index[name_index]
        for name_index in class_name_indexes
        if name_index in utf8_by_index
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/artifact/test_classfile.py -v`
Expected: PASS — 6 tests

- [ ] **Step 5: Verify lint and types**

Run: `cd backend && .venv/bin/ruff check app tests && .venv/bin/mypy app`
Expected: no findings

- [ ] **Step 6: Commit**

```bash
cd backend
git add app/artifact/classfile.py tests/artifact/test_classfile.py
git commit -m "Parse Java class file constant pools

Every class a compiled class references appears in its constant pool, giving
compiled-reality evidence of what the code touches — stronger than source
search, which formatting and star imports defeat.

Long and Double occupy two pool indices each; advancing by one desynchronises
the rest of the pool and silently returns wrong names. For a Tier 2 check that
would mean wrongly concluding a vulnerable class is unreferenced, so it is
tested directly. Unknown tags raise rather than returning a partial set, for
the same reason."
```

---

### Task 3: Artifact inventory

Read a JAR or WAR and report its layout, its bundled libraries with hashes, its application classes, and any embedded git metadata.

**Files:**
- Create: `backend/app/artifact/inventory.py`
- Test: `backend/tests/artifact/test_inventory.py`

**Interfaces:**
- Consumes: `errors.MalformedArtifact` (Task 1); factories (Task 1)
- Produces:
  - `Layout` enum with members `SPRING_BOOT_FAT`, `WAR`, `PLAIN_JAR`
  - `Library` dataclass: `path: str`, `name: str`, `sha1: str`, `sha256: str`, `size: int`
  - `Inventory` dataclass: `layout: Layout`, `libraries: list[Library]`, `app_classes: dict[str, bytes]`, `git_properties: dict[str, str]`
  - `Inventory.commit_sha() -> str | None`
  - `Inventory.repository_url() -> str | None`
  - `Inventory.library_sha1s() -> dict[str, str]` — sha1 to library name
  - `inspect_archive(data: bytes) -> Inventory`

- [ ] **Step 1: Write the failing test**

`backend/tests/artifact/test_inventory.py`:

```python
import hashlib

import pytest

from app.artifact.errors import MalformedArtifact
from app.artifact.inventory import Layout, inspect_archive
from tests.artifact.factories import make_class_file, make_jar, make_spring_boot_jar, make_war


def test_detects_spring_boot_layout():
    raw = make_spring_boot_jar(app_classes={"com/example/App.class": b"x"}, libraries={})
    assert inspect_archive(raw).layout is Layout.SPRING_BOOT_FAT


def test_detects_war_layout():
    raw = make_war(app_classes={"com/example/App.class": b"x"}, libraries={})
    assert inspect_archive(raw).layout is Layout.WAR


def test_detects_plain_jar_layout():
    raw = make_jar({"com/example/App.class": b"x"})
    assert inspect_archive(raw).layout is Layout.PLAIN_JAR


def test_hashes_bundled_libraries():
    lib = make_jar({"org/apache/commons/text/StringSubstitutor.class": b"y"})
    raw = make_spring_boot_jar(app_classes={}, libraries={"commons-text-1.9.jar": lib})

    inventory = inspect_archive(raw)

    assert len(inventory.libraries) == 1
    library = inventory.libraries[0]
    assert library.name == "commons-text-1.9.jar"
    assert library.path == "BOOT-INF/lib/commons-text-1.9.jar"
    assert library.sha1 == hashlib.sha1(lib).hexdigest()
    assert library.sha256 == hashlib.sha256(lib).hexdigest()
    assert library.size == len(lib)


def test_collects_application_classes_stripped_of_layout_prefix():
    raw = make_spring_boot_jar(
        app_classes={"com/example/App.class": b"x", "com/example/Other.class": b"y"},
        libraries={"lib.jar": make_jar({})},
    )
    inventory = inspect_archive(raw)
    assert set(inventory.app_classes) == {"com/example/App.class", "com/example/Other.class"}


def test_library_classes_are_not_counted_as_application_classes():
    # A library referencing a vulnerable class says nothing about whether the
    # application does. Only the application's own bytecode is Tier 2 evidence.
    lib = make_jar({"org/thirdparty/Internal.class": b"y"})
    raw = make_spring_boot_jar(app_classes={"com/example/App.class": b"x"}, libraries={"l.jar": lib})
    assert set(inspect_archive(raw).app_classes) == {"com/example/App.class"}


def test_reads_embedded_git_properties():
    raw = make_spring_boot_jar(
        app_classes={},
        libraries={},
        git_properties={
            "git.commit.id.full": "4a9f1c2e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39",
            "git.branch": "release/1.14",
            "git.remote.origin.url": "https://bitbucket.example/scm/pay/payments-api.git",
        },
    )
    inventory = inspect_archive(raw)
    assert inventory.commit_sha() == "4a9f1c2e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39"
    assert inventory.repository_url() == "https://bitbucket.example/scm/pay/payments-api.git"


def test_missing_git_properties_yields_none():
    raw = make_jar({"com/example/App.class": b"x"})
    inventory = inspect_archive(raw)
    assert inventory.commit_sha() is None
    assert inventory.repository_url() is None


def test_library_sha1s_maps_hash_to_name():
    lib = make_jar({})
    raw = make_spring_boot_jar(app_classes={}, libraries={"commons-text-1.9.jar": lib})
    assert inspect_archive(raw).library_sha1s() == {
        hashlib.sha1(lib).hexdigest(): "commons-text-1.9.jar"
    }


def test_rejects_input_that_is_not_an_archive():
    with pytest.raises(MalformedArtifact):
        inspect_archive(b"not a zip at all")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/artifact/test_inventory.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.artifact.inventory'`

- [ ] **Step 3: Write the inventory reader**

`backend/app/artifact/inventory.py`:

```python
"""JAR and WAR structure: what an artifact actually contains.

A dependency listed in a manifest is not the same as a class present in the
shipped artifact. Shading, minimization, ``<filters>`` and tree-shaking all
remove code the manifest still advertises, which is exactly the gap between
what a scanner reports and what actually ships.
"""

from __future__ import annotations

import hashlib
import io
import posixpath
import zipfile
from dataclasses import dataclass, field
from enum import Enum

from app.artifact.errors import MalformedArtifact


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


def inspect_archive(data: bytes) -> Inventory:
    """Read a JAR or WAR and report what it contains.

    Raises:
        MalformedArtifact: the bytes are not a readable ZIP archive.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise MalformedArtifact(f"not a readable archive: {exc}") from exc

    with archive:
        layout = _detect_layout(archive)
        class_prefix, library_prefix = _PREFIXES[layout]

        libraries: list[Library] = []
        app_classes: dict[str, bytes] = {}
        git_properties: dict[str, str] = {}
        git_properties_is_application_own = False

        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename

            if library_prefix and name.startswith(library_prefix) and name.endswith(".jar"):
                payload = archive.read(name)
                libraries.append(
                    Library(
                        path=name,
                        name=posixpath.basename(name),
                        sha1=hashlib.sha1(payload).hexdigest(),
                        sha256=hashlib.sha256(payload).hexdigest(),
                        size=len(payload),
                    )
                )
            elif name.endswith(".class") and _is_application_class(name, class_prefix, layout):
                app_classes[name.removeprefix(class_prefix)] = archive.read(name)
            elif posixpath.basename(name) == "git.properties":
                # A fat JAR can carry git.properties for bundled libraries too;
                # the application's own copy wins.
                is_own = bool(class_prefix) and name.startswith(class_prefix)
                if not git_properties or (is_own and not git_properties_is_application_own):
                    git_properties = _parse_properties(archive.read(name))
                    git_properties_is_application_own = is_own

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
        if info.filename.startswith("BOOT-INF/"):
            return Layout.SPRING_BOOT_FAT  # wins: a Boot fat WAR has both
        if info.filename.startswith("WEB-INF/"):
            has_web_inf = True
    return Layout.WAR if has_web_inf else Layout.PLAIN_JAR


def _is_application_class(name: str, class_prefix: str, layout: Layout) -> bool:
    """Distinguish the application's own compiled code from everything else."""
    if layout is not Layout.PLAIN_JAR:
        return name.startswith(class_prefix)
    return not name.startswith(_NON_APPLICATION_PREFIXES)


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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/artifact/test_inventory.py -v`
Expected: PASS — 10 tests

- [ ] **Step 5: Verify lint and types**

Run: `cd backend && .venv/bin/ruff check app tests && .venv/bin/mypy app`
Expected: no findings

- [ ] **Step 6: Commit**

```bash
cd backend
git add app/artifact/inventory.py tests/artifact/test_inventory.py
git commit -m "Read JAR and WAR structure

Reports layout, bundled libraries with hashes, the application's own classes,
and embedded git metadata.

Layout is inferred from entry prefixes rather than the file extension: Spring
Boot applications are often packaged as .war and other .war files are not Boot
applications. Library classes are excluded from app_classes because a library
referencing a vulnerable class says nothing about whether the application does."
```

---

### Task 4: Class presence check — Tier 1 proof

The single highest-confidence check available: if the vulnerable class is not in the artifact, it cannot execute.

**Files:**
- Create: `backend/app/artifact/presence.py`
- Test: `backend/tests/artifact/test_presence.py`

**Interfaces:**
- Consumes: `errors.MalformedArtifact` (Task 1)
- Produces:
  - `normalize_class_path(name: str) -> str` — accepts dotted FQCN, JVM internal form, with or without `.class`; returns JVM internal form with the suffix
  - `contains_class(data: bytes, class_path: str, *, max_depth: int = 3) -> bool`

- [ ] **Step 1: Write the failing test**

`backend/tests/artifact/test_presence.py`:

```python
import pytest

from app.artifact.errors import MalformedArtifact
from app.artifact.presence import contains_class, normalize_class_path
from tests.artifact.factories import make_jar, make_spring_boot_jar, make_war


TARGET = "org/apache/commons/text/StringSubstitutor.class"


def test_normalizes_dotted_class_name():
    assert normalize_class_path("com.example.Service") == "com/example/Service.class"


def test_normalizes_internal_form_without_suffix():
    assert normalize_class_path("com/example/Service") == "com/example/Service.class"


def test_leaves_already_normalized_path_alone():
    assert normalize_class_path("com/example/Service.class") == "com/example/Service.class"


def test_finds_class_in_plain_jar():
    assert contains_class(make_jar({TARGET: b"x"}), TARGET) is True


def test_finds_class_inside_a_bundled_library():
    # The Spring Boot case: the vulnerable class lives in a nested JAR, so a
    # flat entry listing of the outer archive would miss it entirely.
    lib = make_jar({TARGET: b"x"})
    raw = make_spring_boot_jar(app_classes={}, libraries={"commons-text-1.9.jar": lib})
    assert contains_class(raw, TARGET) is True


def test_finds_application_class_despite_layout_prefix():
    raw = make_spring_boot_jar(app_classes={"com/example/App.class": b"x"}, libraries={})
    assert contains_class(raw, "com/example/App.class") is True


def test_reports_absence_when_class_is_not_present():
    # This is the Tier 1 proof path: a False here clears a finding.
    lib = make_jar({"org/apache/commons/text/StrSubstitutor.class": b"x"})
    raw = make_spring_boot_jar(app_classes={}, libraries={"commons-text-1.9.jar": lib})
    assert contains_class(raw, TARGET) is False


def test_accepts_dotted_name_from_caller():
    raw = make_jar({TARGET: b"x"})
    assert contains_class(raw, "org.apache.commons.text.StringSubstitutor") is True


def test_malformed_nested_library_raises_rather_than_reporting_absence():
    # A corrupt nested JAR must not be read as "the class is not there".
    # Returning False here would turn a parse failure into Tier 1 proof and
    # clear a finding that was never examined.
    raw = make_spring_boot_jar(app_classes={}, libraries={"broken.jar": b"definitely not a zip"})
    with pytest.raises(MalformedArtifact):
        contains_class(raw, TARGET)


def test_malformed_outer_artifact_raises():
    with pytest.raises(MalformedArtifact):
        contains_class(b"not a zip", TARGET)


def test_depth_limit_is_enforced_rather_than_recursing_forever():
    inner = make_jar({TARGET: b"x"})
    middle = make_jar({"nested.jar": inner})
    outer = make_jar({"outer.jar": middle})
    assert contains_class(outer, TARGET, max_depth=3) is True
    with pytest.raises(MalformedArtifact, match="nesting depth"):
        contains_class(outer, TARGET, max_depth=1)


def test_war_layout_is_searched():
    lib = make_jar({TARGET: b"x"})
    raw = make_war(app_classes={}, libraries={"commons-text-1.9.jar": lib})
    assert contains_class(raw, TARGET) is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/artifact/test_presence.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.artifact.presence'`

- [ ] **Step 3: Write the presence check**

`backend/app/artifact/presence.py`:

```python
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

from app.artifact.errors import MalformedArtifact

_LAYOUT_CLASS_PREFIXES = ("BOOT-INF/classes/", "WEB-INF/classes/")


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


def contains_class(data: bytes, class_path: str, *, max_depth: int = 3) -> bool:
    """Report whether ``class_path`` is present anywhere in the artifact.

    Searches the application's own classes and recurses into bundled JARs,
    which is where the vulnerable class usually lives.

    Args:
        data: the artifact bytes.
        class_path: the class to look for, in any of the accepted forms.
        max_depth: how many levels of nested archive to descend. Spring Boot
            nests one level; shaded uber-JARs can nest deeper. The limit exists
            so a malicious or pathological archive cannot cause unbounded work.

    Raises:
        MalformedArtifact: the artifact or a nested archive could not be read,
            or nesting exceeded ``max_depth``. Never returns ``False`` for
            these — see the module docstring.
    """
    return _search(data, normalize_class_path(class_path), depth=0, max_depth=max_depth)


def _search(data: bytes, target: str, *, depth: int, max_depth: int) -> bool:
    if depth >= max_depth:
        raise MalformedArtifact(
            f"archive nesting depth exceeded {max_depth} while looking for {target}; "
            "refusing to report absence without having searched exhaustively"
        )

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise MalformedArtifact(f"not a readable archive: {exc}") from exc

    with archive:
        nested: list[str] = []
        for info in archive.infolist():
            if info.is_dir():
                continue
            if _matches(info.filename, target):
                return True
            if info.filename.endswith(".jar"):
                nested.append(info.filename)

        for name in nested:
            try:
                payload = archive.read(name)
            except (zipfile.BadZipFile, OSError) as exc:
                raise MalformedArtifact(f"could not read nested archive {name}: {exc}") from exc
            try:
                if _search(payload, target, depth=depth + 1, max_depth=max_depth):
                    return True
            except MalformedArtifact as exc:
                raise MalformedArtifact(f"while inspecting nested archive {name}: {exc}") from exc

    return False


def _matches(entry: str, target: str) -> bool:
    """Compare an archive entry against the target, allowing layout prefixes.

    Callers pass the bare JVM name; the artifact may store it under a layout
    prefix depending on how it was packaged.
    """
    if entry == target:
        return True
    return any(
        entry.removeprefix(prefix) == target
        for prefix in _LAYOUT_CLASS_PREFIXES
        if entry.startswith(prefix)
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/artifact/test_presence.py -v`
Expected: PASS — 12 tests

- [ ] **Step 5: Verify lint and types**

Run: `cd backend && .venv/bin/ruff check app tests && .venv/bin/mypy app`
Expected: no findings

- [ ] **Step 6: Commit**

```bash
cd backend
git add app/artifact/presence.py tests/artifact/test_presence.py
git commit -m "Add Tier 1 class presence check

If the vulnerable class is not in the shipped artifact it cannot execute, which
is the highest-confidence evidence available. Recurses into bundled JARs, since
that is where the class usually lives.

Every failure path raises rather than returning False. A False here clears a
finding, so reporting a corrupt archive or exceeded nesting depth as 'not
present' would manufacture Tier 1 proof out of a bug."
```

---

### Task 5: Application reference scan — Tier 2 evidence

Collect every class the application's own bytecode references, and detect the dynamic-dispatch escape hatches that make that evidence unsafe to act on alone.

**Files:**
- Create: `backend/app/artifact/references.py`
- Test: `backend/tests/artifact/test_references.py`

**Interfaces:**
- Consumes: `Inventory` (Task 3), `referenced_classes` (Task 2), `normalize_class_path` (Task 4)
- Produces:
  - `EscapeHatch` dataclass: `kind: str`, `location: str`
  - `ReferenceScan` dataclass: `referenced: set[str]`, `escape_hatches: list[EscapeHatch]`, `classes_scanned: int`, `unreadable_classes: list[str]`
  - `ReferenceScan.references(class_path: str) -> bool`
  - `ReferenceScan.is_conclusive() -> bool`
  - `scan_references(inventory: Inventory) -> ReferenceScan`

- [ ] **Step 1: Write the failing test**

`backend/tests/artifact/test_references.py`:

```python
from app.artifact.inventory import inspect_archive
from app.artifact.references import scan_references
from tests.artifact.factories import make_class_file, make_spring_boot_jar

VULNERABLE = "org/apache/commons/text/StringSubstitutor"


def _inventory_with(app_classes: dict[str, bytes]):
    return inspect_archive(make_spring_boot_jar(app_classes=app_classes, libraries={}))


def test_collects_references_from_application_bytecode():
    inventory = _inventory_with({"com/example/App.class": make_class_file([VULNERABLE])})
    scan = scan_references(inventory)
    assert scan.references(VULNERABLE) is True
    assert scan.classes_scanned == 1


def test_reports_no_reference_when_the_class_is_never_touched():
    inventory = _inventory_with(
        {"com/example/App.class": make_class_file(["java/lang/String"])}
    )
    scan = scan_references(inventory)
    assert scan.references(VULNERABLE) is False


def test_accepts_the_dotted_and_suffixed_forms():
    inventory = _inventory_with({"com/example/App.class": make_class_file([VULNERABLE])})
    scan = scan_references(inventory)
    assert scan.references("org.apache.commons.text.StringSubstitutor") is True
    assert scan.references(f"{VULNERABLE}.class") is True


def test_detects_reflection_escape_hatch():
    # Class.forName reaches classes that never appear in a constant pool, so
    # "no reference found" stops being evidence of non-use.
    inventory = _inventory_with(
        {"com/example/App.class": make_class_file(["java/lang/Class", "java/lang/String"])}
    )
    scan = scan_references(inventory)
    assert any(hatch.kind == "reflection" for hatch in scan.escape_hatches)
    assert scan.is_conclusive() is False


def test_detects_service_loader_escape_hatch():
    inventory = _inventory_with(
        {"com/example/App.class": make_class_file(["java/util/ServiceLoader"])}
    )
    scan = scan_references(inventory)
    assert any(hatch.kind == "service_loader" for hatch in scan.escape_hatches)
    assert scan.is_conclusive() is False


def test_detects_spring_component_scanning():
    inventory = _inventory_with(
        {
            "com/example/App.class": make_class_file(
                ["org/springframework/context/annotation/ComponentScan"]
            )
        }
    )
    scan = scan_references(inventory)
    assert any(hatch.kind == "component_scan" for hatch in scan.escape_hatches)


def test_scan_is_conclusive_when_no_escape_hatch_is_present():
    inventory = _inventory_with(
        {"com/example/App.class": make_class_file(["java/lang/String"])}
    )
    assert scan_references(inventory).is_conclusive() is True


def test_unreadable_class_is_recorded_and_makes_the_scan_inconclusive():
    # A class we could not parse might be the one that references the target.
    # Silently skipping it would understate the references and could clear a
    # finding on incomplete evidence.
    inventory = _inventory_with(
        {
            "com/example/Good.class": make_class_file(["java/lang/String"]),
            "com/example/Bad.class": b"not a class file",
        }
    )
    scan = scan_references(inventory)
    assert scan.unreadable_classes == ["com/example/Bad.class"]
    assert scan.is_conclusive() is False
    assert scan.classes_scanned == 1
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/artifact/test_references.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.artifact.references'`

- [ ] **Step 3: Write the reference scanner**

`backend/app/artifact/references.py`:

```python
"""Tier 2 evidence: what the application's own bytecode actually references.

Reads the constant pool of every class the application compiled and collects
the classes they name. If the vulnerable class never appears, the application
does not statically reference it.

That is evidence, not proof. Reflection, ``ServiceLoader``, Spring component
scanning and other dynamic dispatch all reach classes that never appear in a
constant pool. This module therefore also detects those escape hatches, and
:meth:`ReferenceScan.is_conclusive` reports whether the absence of a reference
can be trusted. A scan that is not conclusive must route to human review rather
than clear a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.artifact.classfile import referenced_classes
from app.artifact.errors import ArtifactError
from app.artifact.inventory import Inventory
from app.artifact.presence import normalize_class_path

#: Classes whose presence in a constant pool indicates the application can
#: reach code that static analysis cannot see. Mapped to the escape hatch kind
#: reported to the reviewer.
_ESCAPE_HATCH_MARKERS: dict[str, str] = {
    "java/lang/Class": "reflection",
    "java/lang/reflect/Method": "reflection",
    "java/lang/reflect/Constructor": "reflection",
    "java/util/ServiceLoader": "service_loader",
    "org/springframework/context/annotation/ComponentScan": "component_scan",
    "org/springframework/context/annotation/Import": "component_scan",
    "javax/naming/InitialContext": "jndi",
    "javax/naming/Context": "jndi",
    "org/springframework/expression/spel/standard/SpelExpressionParser": "spel",
}


@dataclass(frozen=True, slots=True)
class EscapeHatch:
    """A construct that lets the application reach code static analysis misses."""

    kind: str
    location: str


@dataclass(frozen=True, slots=True)
class ReferenceScan:
    """The result of reading every application class's constant pool."""

    referenced: set[str] = field(default_factory=set)
    escape_hatches: list[EscapeHatch] = field(default_factory=list)
    classes_scanned: int = 0

    #: Classes that could not be parsed. Any entry here means the scan did not
    #: see everything, so absence of a reference proves nothing.
    unreadable_classes: list[str] = field(default_factory=list)

    def references(self, class_path: str) -> bool:
        """Whether the application statically references ``class_path``."""
        return normalize_class_path(class_path).removesuffix(".class") in self.referenced

    def is_conclusive(self) -> bool:
        """Whether absence of a reference can be trusted as evidence.

        False when any dynamic-dispatch escape hatch was found, or when any
        class could not be read. In both cases the application may reach code
        this scan did not observe.
        """
        return not self.escape_hatches and not self.unreadable_classes


def scan_references(inventory: Inventory) -> ReferenceScan:
    """Read every application class in ``inventory`` and collect its references.

    Only the application's own classes are read. A bundled library referencing
    a vulnerable class says nothing about whether the application does, so
    including library classes would inflate the reference set and destroy the
    evidence's value.
    """
    referenced: set[str] = set()
    hatches: list[EscapeHatch] = []
    unreadable: list[str] = []
    scanned = 0

    for path, payload in sorted(inventory.app_classes.items()):
        try:
            names = referenced_classes(payload)
        except ArtifactError:
            unreadable.append(path)
            continue

        scanned += 1
        referenced |= names
        hatches.extend(
            EscapeHatch(kind=_ESCAPE_HATCH_MARKERS[name], location=path)
            for name in sorted(names)
            if name in _ESCAPE_HATCH_MARKERS
        )

    return ReferenceScan(
        referenced=referenced,
        escape_hatches=hatches,
        classes_scanned=scanned,
        unreadable_classes=unreadable,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/artifact/test_references.py -v`
Expected: PASS — 8 tests

- [ ] **Step 5: Verify lint and types**

Run: `cd backend && .venv/bin/ruff check app tests && .venv/bin/mypy app`
Expected: no findings

- [ ] **Step 6: Commit**

```bash
cd backend
git add app/artifact/references.py tests/artifact/test_references.py
git commit -m "Scan application bytecode for class references

Collects every class the application's own compiled code names, and detects the
dynamic-dispatch constructs — reflection, ServiceLoader, component scanning,
JNDI, SpEL — that let it reach code a constant pool never mentions.

is_conclusive() reports whether absence of a reference can be trusted. It is
false when an escape hatch is present or when any class failed to parse, since
in both cases the scan did not see everything."
```

---

### Task 6: Container image extraction

For containerised applications the artifact is an image, not a binary. Walk the layers and recover the application archive so every check above applies unchanged.

**Files:**
- Create: `backend/app/artifact/image.py`
- Test: `backend/tests/artifact/test_image.py`
- Modify: `backend/tests/artifact/factories.py` — add `make_layer`

**Interfaces:**
- Consumes: `errors.MalformedArtifact` (Task 1)
- Produces:
  - `FoundArchive` dataclass: `path: str`, `layer_index: int`, `data: bytes`
  - `make_layer(entries: dict[str, bytes], *, compress: bool = True) -> bytes` (test factory)
  - `find_application_archives(layers: list[bytes], *, min_size: int = 1024) -> list[FoundArchive]`

- [ ] **Step 1: Add the layer factory**

Append to `backend/tests/artifact/factories.py`:

```python
def make_layer(entries: dict[str, bytes], *, compress: bool = True) -> bytes:
    """Build a container image layer: a TAR, gzipped by default.

    Image layers are plain TARs; registries serve them gzipped. Both forms
    occur in practice depending on how the image was pulled.
    """
    import tarfile

    buffer = io.BytesIO()
    mode = "w:gz" if compress else "w"
    with tarfile.open(fileobj=buffer, mode=mode) as tf:  # type: ignore[call-overload]
        for name, payload in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()
```

- [ ] **Step 2: Write the failing test**

`backend/tests/artifact/test_image.py`:

```python
import pytest

from app.artifact.errors import MalformedArtifact
from app.artifact.image import find_application_archives
from tests.artifact.factories import make_jar, make_layer, make_spring_boot_jar

APP_JAR = make_spring_boot_jar(
    app_classes={"com/example/App.class": b"x" * 2048}, libraries={}
)


def test_finds_a_jar_in_a_single_layer():
    layers = [make_layer({"app/application.jar": APP_JAR})]
    found = find_application_archives(layers)
    assert len(found) == 1
    assert found[0].path == "app/application.jar"
    assert found[0].layer_index == 0
    assert found[0].data == APP_JAR


def test_finds_archives_across_multiple_layers():
    layers = [
        make_layer({"usr/lib/jvm/placeholder": b"z" * 2048}),
        make_layer({"opt/app/service.war": APP_JAR}),
    ]
    found = find_application_archives(layers)
    assert [(f.path, f.layer_index) for f in found] == [("opt/app/service.war", 1)]


def test_reads_uncompressed_layers():
    layers = [make_layer({"app/application.jar": APP_JAR}, compress=False)]
    assert len(find_application_archives(layers)) == 1


def test_ignores_non_archive_entries():
    layers = [make_layer({"etc/passwd": b"root:x:0:0:" * 200, "app/README": b"hello" * 500})]
    assert find_application_archives(layers) == []


def test_ignores_archives_below_the_size_floor():
    # JRE-bundled stubs and tiny helper JARs are not the application.
    layers = [make_layer({"app/tiny.jar": make_jar({})})]
    assert find_application_archives(layers, min_size=4096) == []


def test_later_layer_shadows_an_earlier_one_at_the_same_path():
    # Image layers stack; a rebuild replacing the JAR leaves the old one in an
    # earlier layer. Analysing the stale copy would assess a build that is not
    # the one running, so the last write must win.
    old = make_spring_boot_jar(app_classes={"com/example/Old.class": b"o" * 2048}, libraries={})
    layers = [
        make_layer({"app/application.jar": old}),
        make_layer({"app/application.jar": APP_JAR}),
    ]
    found = find_application_archives(layers)
    assert len(found) == 1
    assert found[0].data == APP_JAR
    assert found[0].layer_index == 1


def test_whiteout_entry_removes_an_earlier_archive():
    # OverlayFS deletions appear as .wh.<name> marker files.
    layers = [
        make_layer({"app/application.jar": APP_JAR}),
        make_layer({"app/.wh.application.jar": b""}),
    ]
    assert find_application_archives(layers) == []


def test_malformed_layer_raises_rather_than_being_skipped():
    with pytest.raises(MalformedArtifact):
        find_application_archives([b"not a tar archive at all"])
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/artifact/test_image.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.artifact.image'`

- [ ] **Step 4: Write the image walker**

`backend/app/artifact/image.py`:

```python
"""Recover the application archive from a container image.

For containerised applications the artifact published to the registry is an
image, not a binary. An image is a stack of TAR layers; the application JAR or
WAR is a file inside one of them. Once recovered, every other check in this
package applies to it unchanged.

Layer ordering matters. Layers stack, so a later layer writing the same path
replaces the earlier one, and a deletion appears as an OverlayFS whiteout
marker. Analysing a shadowed copy would assess a build that is not the one
running.
"""

from __future__ import annotations

import io
import posixpath
import tarfile
from dataclasses import dataclass

from app.artifact.errors import MalformedArtifact

_ARCHIVE_SUFFIXES = (".jar", ".war", ".ear")
_WHITEOUT_PREFIX = ".wh."

#: Archives smaller than this are JRE stubs, helper JARs, and build tooling
#: rather than the application. The floor is deliberately low: excluding a real
#: application is worse than including a stub, which later checks discard.
_DEFAULT_MIN_SIZE = 1024


@dataclass(frozen=True, slots=True)
class FoundArchive:
    """An application archive recovered from an image layer."""

    path: str
    layer_index: int
    data: bytes


def find_application_archives(
    layers: list[bytes], *, min_size: int = _DEFAULT_MIN_SIZE
) -> list[FoundArchive]:
    """Recover candidate application archives from ``layers``.

    Args:
        layers: layer blobs in image order, oldest first. Gzipped or plain TAR.
        min_size: ignore archives smaller than this many bytes.

    Returns:
        Surviving archives after layer shadowing and whiteouts are applied,
        ordered by path.

    Raises:
        MalformedArtifact: a layer could not be read as a TAR. Skipping it
            would risk reporting that the application archive is absent when it
            was merely unreadable.
    """
    # Path to the newest archive written there. Later layers overwrite.
    surviving: dict[str, FoundArchive] = {}

    for index, blob in enumerate(layers):
        for name, payload in _walk_layer(blob, index):
            base = posixpath.basename(name)

            if base.startswith(_WHITEOUT_PREFIX):
                deleted = posixpath.join(posixpath.dirname(name), base[len(_WHITEOUT_PREFIX) :])
                surviving.pop(deleted, None)
                continue

            if not name.endswith(_ARCHIVE_SUFFIXES) or len(payload) < min_size:
                continue

            surviving[name] = FoundArchive(path=name, layer_index=index, data=payload)

    return [surviving[path] for path in sorted(surviving)]


def _walk_layer(blob: bytes, index: int) -> list[tuple[str, bytes]]:
    """Return every regular file in one layer as (normalised path, contents)."""
    try:
        # mode "r:*" auto-detects gzip, bzip2, xz, and uncompressed.
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
            entries: list[tuple[str, bytes]] = []
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                handle = tf.extractfile(member)
                if handle is None:
                    continue
                entries.append((_normalise(member.name), handle.read()))
            return entries
    except tarfile.TarError as exc:
        raise MalformedArtifact(f"layer {index} is not a readable tar archive: {exc}") from exc


def _normalise(name: str) -> str:
    """Strip the leading ``./`` many tar writers emit, so paths compare equal."""
    return name[2:] if name.startswith("./") else name
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/artifact/test_image.py -v`
Expected: PASS — 8 tests

- [ ] **Step 6: Verify lint and types**

Run: `cd backend && .venv/bin/ruff check app tests && .venv/bin/mypy app`
Expected: no findings

- [ ] **Step 7: Commit**

```bash
cd backend
git add app/artifact/image.py tests/artifact/test_image.py tests/artifact/factories.py
git commit -m "Recover application archives from container image layers

Containerised applications publish an image, not a binary. Walking the layers
recovers the JAR or WAR so every other check applies unchanged.

Layer ordering is honoured: a later layer writing the same path shadows the
earlier one, and OverlayFS whiteout markers delete. Analysing a shadowed copy
would assess a build that is not the one running. An unreadable layer raises
rather than being skipped, since skipping could report the application archive
as absent when it was merely unreadable."
```

---

### Task 7: Provenance fingerprint

Prove the artifact is the build the report describes, using only the two things already in hand.

**Files:**
- Create: `backend/app/provenance/__init__.py`
- Create: `backend/app/provenance/fingerprint.py`
- Test: `backend/tests/provenance/__init__.py`
- Test: `backend/tests/provenance/test_fingerprint.py`

**Interfaces:**
- Consumes: `Inventory` (Task 3)
- Produces:
  - `Verdict` enum: `MATCH`, `MISMATCH`, `INSUFFICIENT_DATA`
  - `FingerprintResult` dataclass: `verdict`, `matched: int`, `report_total: int`, `unmatched_report_hashes: list[str]`, `ratio: float`
  - `FingerprintResult.summary() -> str`
  - `compare(report_component_sha1s: set[str], inventory: Inventory, *, threshold: float = 0.95, minimum_components: int = 5) -> FingerprintResult`

- [ ] **Step 1: Write the failing test**

`backend/tests/provenance/test_fingerprint.py`:

```python
import hashlib

from app.artifact.inventory import inspect_archive
from app.provenance.fingerprint import Verdict, compare
from tests.artifact.factories import make_jar, make_spring_boot_jar


def _inventory(library_payloads: dict[str, bytes]):
    return inspect_archive(make_spring_boot_jar(app_classes={}, libraries=library_payloads))


def _libs(count: int) -> dict[str, bytes]:
    return {f"lib-{i}.jar": make_jar({f"pkg/C{i}.class": bytes([i])}) for i in range(count)}


def test_identical_component_sets_match():
    payloads = _libs(10)
    inventory = _inventory(payloads)
    report = {hashlib.sha1(p).hexdigest() for p in payloads.values()}

    result = compare(report, inventory)

    assert result.verdict is Verdict.MATCH
    assert result.matched == 10
    assert result.ratio == 1.0


def test_completely_different_artifact_is_a_mismatch():
    inventory = _inventory(_libs(10))
    # Hashes of payloads that appear nowhere in the artifact.
    report = {hashlib.sha1(f"other-{i}".encode()).hexdigest() for i in range(10)}

    result = compare(report, inventory)

    assert result.verdict is Verdict.MISMATCH
    assert result.matched == 0


def test_small_divergence_still_matches_within_threshold():
    # A rebuild can legitimately differ by a component or two — a timestamped
    # jar, a reproducibility gap. The threshold accommodates that without
    # accepting a different application.
    payloads = _libs(100)
    inventory = _inventory(payloads)
    hashes = [hashlib.sha1(p).hexdigest() for p in payloads.values()]
    report = set(hashes[:97]) | {hashlib.sha1(b"extra-1").hexdigest()}

    result = compare(report, inventory)

    assert result.verdict is Verdict.MATCH
    assert result.matched == 97


def test_divergence_beyond_threshold_is_a_mismatch():
    payloads = _libs(100)
    inventory = _inventory(payloads)
    hashes = [hashlib.sha1(p).hexdigest() for p in payloads.values()]
    report = set(hashes[:50]) | {hashlib.sha1(f"e{i}".encode()).hexdigest() for i in range(50)}

    assert compare(report, inventory).verdict is Verdict.MISMATCH


def test_too_few_components_is_insufficient_rather_than_a_match():
    # Two components matching two components is not evidence of anything. A
    # MATCH here would admit an unrelated artifact on a coincidence.
    payloads = _libs(2)
    inventory = _inventory(payloads)
    report = {hashlib.sha1(p).hexdigest() for p in payloads.values()}

    result = compare(report, inventory)

    assert result.verdict is Verdict.INSUFFICIENT_DATA


def test_empty_report_is_insufficient():
    assert compare(set(), _inventory(_libs(10))).verdict is Verdict.INSUFFICIENT_DATA


def test_unmatched_hashes_are_reported_for_the_reviewer():
    payloads = _libs(10)
    inventory = _inventory(payloads)
    missing = hashlib.sha1(b"not-in-artifact").hexdigest()
    report = {hashlib.sha1(p).hexdigest() for p in payloads.values()} | {missing}

    result = compare(report, inventory)

    assert missing in result.unmatched_report_hashes


def test_summary_is_human_readable():
    payloads = _libs(10)
    inventory = _inventory(payloads)
    report = {hashlib.sha1(p).hexdigest() for p in payloads.values()}
    assert "10/10" in compare(report, inventory).summary()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/provenance/test_fingerprint.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.provenance.fingerprint'`

Create `backend/app/provenance/__init__.py` and `backend/tests/provenance/__init__.py` as empty files.

- [ ] **Step 3: Write the fingerprint comparison**

`backend/app/provenance/fingerprint.py`:

```python
"""Prove an artifact is the build a scan report describes.

The report lists every component the scanner identified, each with a hash. The
artifact contains bundled libraries, which hash to the same values if it is the
same build. Comparing the two sets establishes provenance using only what is
already in hand — no build metadata, no CI cooperation, no changes to anyone
else's pipeline.

This runs at admission. An artifact that does not match the report is a
different build, and every piece of evidence derived from it would describe
software that was never scanned.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from app.artifact.inventory import Inventory

#: Rebuilds can legitimately differ by a component or two — a timestamped JAR,
#: a reproducibility gap. Below this proportion the artifact is a different
#: build rather than a noisy rebuild.
_DEFAULT_THRESHOLD = 0.95

#: Fewer components than this cannot distinguish a genuine match from a
#: coincidence, so the comparison abstains instead of asserting.
_DEFAULT_MINIMUM_COMPONENTS = 5


class Verdict(Enum):
    MATCH = "match"
    MISMATCH = "mismatch"

    #: Too little data to assert either way. Not a pass: the caller must treat
    #: this as "provenance unproven" and fall back to other evidence.
    INSUFFICIENT_DATA = "insufficient_data"


@dataclass(frozen=True, slots=True)
class FingerprintResult:
    verdict: Verdict
    matched: int
    report_total: int
    unmatched_report_hashes: list[str]
    ratio: float

    def summary(self) -> str:
        """A one-line description for the reviewer and the audit record."""
        return (
            f"{self.matched}/{self.report_total} report components found in the artifact "
            f"({self.ratio:.0%}) — {self.verdict.value}"
        )


def compare(
    report_component_sha1s: set[str],
    inventory: Inventory,
    *,
    threshold: float = _DEFAULT_THRESHOLD,
    minimum_components: int = _DEFAULT_MINIMUM_COMPONENTS,
) -> FingerprintResult:
    """Compare the report's component hashes against the artifact's libraries.

    Args:
        report_component_sha1s: SHA-1 hashes of every component in the report.
        inventory: the artifact's inventory.
        threshold: proportion of report components that must be present.
        minimum_components: below this the result is INSUFFICIENT_DATA.

    Returns:
        The verdict together with the counts a reviewer needs to judge it.
    """
    report_total = len(report_component_sha1s)
    artifact_hashes = set(inventory.library_sha1s())

    matched_hashes = report_component_sha1s & artifact_hashes
    matched = len(matched_hashes)
    unmatched = sorted(report_component_sha1s - artifact_hashes)
    ratio = matched / report_total if report_total else 0.0

    if report_total < minimum_components:
        verdict = Verdict.INSUFFICIENT_DATA
    elif ratio >= threshold:
        verdict = Verdict.MATCH
    else:
        verdict = Verdict.MISMATCH

    return FingerprintResult(
        verdict=verdict,
        matched=matched,
        report_total=report_total,
        unmatched_report_hashes=unmatched,
        ratio=ratio,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/provenance/ -v`
Expected: PASS — 8 tests

- [ ] **Step 5: Verify lint and types**

Run: `cd backend && .venv/bin/ruff check app tests && .venv/bin/mypy app`
Expected: no findings

- [ ] **Step 6: Commit**

```bash
cd backend
git add app/provenance/ tests/provenance/
git commit -m "Match artifact libraries against report components

Establishes that an artifact is the build a report describes, using only the
report and the artifact — no build metadata and no CI cooperation required.

Runs at admission: an artifact that does not match is a different build, and
evidence derived from it would describe software that was never scanned.
Below a component floor the result is INSUFFICIENT_DATA rather than a match,
since a handful of components cannot distinguish a real match from coincidence."
```

---

### Task 8: Evidence pack assembly and CLI smoke tool

Tie the pieces together into the structure the rule engine will consume, and give the team a way to run it against a real artifact.

**Files:**
- Create: `backend/app/evidence/__init__.py`
- Create: `backend/app/evidence/pack.py`
- Create: `backend/app/artifact/cli.py`
- Test: `backend/tests/evidence/__init__.py`
- Test: `backend/tests/evidence/test_pack.py`

**Interfaces:**
- Consumes: `Inventory`, `inspect_archive` (Task 3); `contains_class` (Task 4); `scan_references`, `ReferenceScan` (Task 5); `compare`, `FingerprintResult` (Task 7)
- Produces:
  - `ComponentEvidence` dataclass: `cve: str`, `class_paths: list[str]`, `class_present: bool`, `referenced: bool`, `reference_scan_conclusive: bool`
  - `EvidencePack` dataclass: `provenance: FingerprintResult`, `inventory_summary: dict[str, object]`, `components: list[ComponentEvidence]`, `escape_hatches: list[EscapeHatch]`
  - `build_pack(artifact: bytes, report_component_sha1s: set[str], findings: dict[str, list[str]]) -> EvidencePack`

- [ ] **Step 1: Write the failing test**

`backend/tests/evidence/test_pack.py`:

```python
import hashlib

from app.evidence.pack import build_pack
from app.provenance.fingerprint import Verdict
from tests.artifact.factories import make_class_file, make_jar, make_spring_boot_jar

VULNERABLE_CLASS = "org/apache/commons/text/StringSubstitutor.class"


def _artifact_with_vulnerable_library():
    vulnerable_lib = make_jar({VULNERABLE_CLASS: b"y" * 512})
    others = {f"lib-{i}.jar": make_jar({f"pkg/C{i}.class": bytes([i])}) for i in range(9)}
    libraries = {"commons-text-1.9.jar": vulnerable_lib, **others}
    artifact = make_spring_boot_jar(
        app_classes={"com/example/App.class": make_class_file(["java/lang/String"])},
        libraries=libraries,
    )
    report_hashes = {hashlib.sha1(p).hexdigest() for p in libraries.values()}
    return artifact, report_hashes


def test_pack_reports_class_present_but_unreferenced():
    artifact, report_hashes = _artifact_with_vulnerable_library()

    pack = build_pack(
        artifact,
        report_component_sha1s=report_hashes,
        findings={"CVE-2022-42889": [VULNERABLE_CLASS]},
    )

    assert pack.provenance.verdict is Verdict.MATCH
    evidence = pack.components[0]
    assert evidence.cve == "CVE-2022-42889"
    assert evidence.class_present is True
    assert evidence.referenced is False
    assert evidence.reference_scan_conclusive is True


def test_pack_reports_class_absent_when_it_does_not_ship():
    artifact, report_hashes = _artifact_with_vulnerable_library()

    pack = build_pack(
        artifact,
        report_component_sha1s=report_hashes,
        findings={"CVE-9999-0001": ["com/absent/Nothing.class"]},
    )

    assert pack.components[0].class_present is False


def test_pack_marks_scan_inconclusive_when_an_escape_hatch_is_present():
    vulnerable_lib = make_jar({VULNERABLE_CLASS: b"y" * 512})
    libraries = {
        "commons-text-1.9.jar": vulnerable_lib,
        **{f"l{i}.jar": make_jar({f"p/C{i}.class": bytes([i])}) for i in range(9)},
    }
    artifact = make_spring_boot_jar(
        app_classes={"com/example/App.class": make_class_file(["java/lang/Class"])},
        libraries=libraries,
    )
    report_hashes = {hashlib.sha1(p).hexdigest() for p in libraries.values()}

    pack = build_pack(
        artifact, report_component_sha1s=report_hashes, findings={"CVE-1": [VULNERABLE_CLASS]}
    )

    assert pack.components[0].reference_scan_conclusive is False
    assert any(h.kind == "reflection" for h in pack.escape_hatches)


def test_pack_records_provenance_mismatch():
    artifact, _ = _artifact_with_vulnerable_library()
    unrelated = {hashlib.sha1(f"x{i}".encode()).hexdigest() for i in range(10)}

    pack = build_pack(artifact, report_component_sha1s=unrelated, findings={})

    assert pack.provenance.verdict is Verdict.MISMATCH


def test_finding_with_several_class_paths_is_present_if_any_ships():
    artifact, report_hashes = _artifact_with_vulnerable_library()

    pack = build_pack(
        artifact,
        report_component_sha1s=report_hashes,
        findings={"CVE-2": ["com/absent/A.class", VULNERABLE_CLASS]},
    )

    assert pack.components[0].class_present is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/evidence/ -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.evidence.pack'`

Create `backend/app/evidence/__init__.py` and `backend/tests/evidence/__init__.py` as empty files.

- [ ] **Step 3: Write the evidence pack**

`backend/app/evidence/pack.py`:

```python
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest tests/evidence/ -v`
Expected: PASS — 5 tests

- [ ] **Step 5: Write the CLI smoke tool**

`backend/app/artifact/cli.py`:

```python
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
```

- [ ] **Step 6: Run the CLI against a synthetic artifact to confirm it works end to end**

```bash
cd backend
PYTHONPATH=. .venv/bin/python -c "
from tests.artifact.factories import make_class_file, make_jar, make_spring_boot_jar
lib = make_jar({'org/apache/commons/text/StringSubstitutor.class': b'y'*512})
raw = make_spring_boot_jar(
    app_classes={'com/example/App.class': make_class_file(['java/lang/String'])},
    libraries={'commons-text-1.9.jar': lib},
    git_properties={'git.commit.id.full': '4a9f1c2'},
)
open('/tmp/smoke.jar','wb').write(raw)
"
PYTHONPATH=. .venv/bin/python -m app.artifact.cli /tmp/smoke.jar org/apache/commons/text/StringSubstitutor
```

Expected: JSON showing `"layout": "spring-boot-fat"`, `"commit_sha": "4a9f1c2"`,
`"reference_scan_conclusive": true`, and a `query` block with
`"present_in_artifact": true` and `"referenced_by_application": false` — the
class ships but the application never touches it.

- [ ] **Step 7: Run the whole suite, lint, and types**

Run: `cd backend && PYTHONPATH=. .venv/bin/pytest -q && .venv/bin/ruff check app tests && .venv/bin/mypy app`
Expected: all tests pass (46 domain + roughly 56 added here), no lint findings, no type errors

- [ ] **Step 8: Commit**

```bash
cd backend
git add app/evidence/ app/artifact/cli.py tests/evidence/
git commit -m "Assemble evidence packs and add an artifact inspection CLI

The pack gives the rule engine facts, never questions: what ships, what the
application references, whether the artifact matches the report. No tier is
assigned and no conclusion drawn — the rule engine is the only place the tier
rules are enforced.

The CLI exists so the team can point the engine at a real artifact and see what
it observes, which is the fastest way to diagnose a determination that looks
wrong."
```

---

## Self-review

**Spec coverage.** Against `docs/design.md`:

| Spec requirement | Task |
|---|---|
| Tier 1 #1 — vulnerable class absent from shipped artifact | 4 |
| Tier 1 #2 — component absent from runtime artifact | 3, 4 |
| Tier 1 #3 — affected submodule not packaged | 3, 4 |
| Tier 2 #6 — constant-pool analysis | 2, 5 |
| Tier 2 anti-check — reflection, ServiceLoader, component scan, JNDI, SpEL | 5 |
| Provenance — dependency-set fingerprint | 7 |
| Provenance — embedded `git.properties` | 3 |
| Container images — layer walking | 6 |
| Evidence pack for the rule engine | 8 |

Deferred to later plans, deliberately: Tier 1 #4 (app decommissioned) needs an inventory adapter; Tier 1 #5 (CVE withdrawn) needs the IQ adapter; Tier 2 #7 (source symbol search) needs Bitbucket; Tier 2 #8–#10 (gadget component, config precondition, runtime version) need report and repository data; all Tier 3 signals need IQ vuln lookup. Every one of those requires an external system and belongs in Plan 2.

**Placeholder scan.** No TBDs, no "add error handling", no "similar to Task N". Every code step contains the code.

**Type consistency.** `Inventory` is produced in Task 3 and consumed in Tasks 5, 7, 8. `ReferenceScan.references()` and `.is_conclusive()` are defined in Task 5 and used in Task 8. `FingerprintResult` is defined in Task 7 and used in Task 8. `normalize_class_path` is defined in Task 4 and used in Task 5. `EscapeHatch` is defined in Task 5 and re-exported through `EvidencePack` in Task 8. `make_layer` is added to the Task 1 factories module by Task 6, which is the only place it is used.

---

## Subsequent plans

**Plan 2 — Adapters and persistence.** Nexus IQ client (report data, vuln lookup carrying KEV and EPSS, remediation, applications scoped to the calling user, determination commit), JFrog client (artifact and image download, build info), Bitbucket client (symbol search), Bedrock adjudicator client, ELK reference reads. All against recorded fixtures so the work happens offline. Plus the SQLAlchemy schema — portable, no `JSONB` operators, no array columns — Alembic migrations, and repositories.

**Plan 3 — Rule engine, services, and API.** The tiered rule engine with its one-directional Tier 3 enforcement, the admission service, evidence collection orchestration, the adjudication service with its refute pass and abstention handling, determination commit, and the FastAPI surface the Angular frontend consumes.
