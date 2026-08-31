"""Builders for synthetic artifacts.

Tests construct the exact structure they depend on rather than relying on
committed binary fixtures, so a test's preconditions are readable in the test.
"""

from __future__ import annotations

import io
import struct
import warnings
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
        # JVMS 4.4.5: Long and Double claim TWO consecutive pool indices —
        # the entry at n, and an unusable slot at n+1. The increment counts
        # indices claimed, not entries written.
        count += 2

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


def make_jar_with_duplicate_entries(entries: list[tuple[str, bytes]]) -> bytes:
    """Build a JAR from an ORDERED sequence of ``(name, payload)`` pairs.

    Unlike :func:`make_jar`, which is backed by a dict and so can hold only
    one payload per name, this accepts a list — so a test can genuinely
    duplicate a raw central-directory entry name (the same name written
    twice via two separate ``writestr`` calls), which a dict of entries
    cannot represent. ``zipfile`` warns on this by design (a normal reader
    can only resolve one of the two occurrences by name afterward); that
    warning is expected here and is suppressed around the write, not
    silenced project-wide.
    """
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, payload in entries:
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
