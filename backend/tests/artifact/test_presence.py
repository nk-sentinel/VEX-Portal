import io
import re
import zipfile
import zlib

import pytest

from app.artifact.errors import MalformedArtifact
from app.artifact.presence import (
    candidate_class_paths,
    collect_class_paths,
    contains_class,
    normalize_class_path,
)
from tests.artifact.factories import (
    make_jar,
    make_jar_with_duplicate_entries,
    make_spring_boot_jar,
    make_war,
)

TARGET = "org/apache/commons/text/StringSubstitutor.class"


def _raw_entry_count(raw: bytes, name: str) -> int:
    """How many central-directory records in ``raw`` are named ``name``."""
    return sum(1 for info in zipfile.ZipFile(io.BytesIO(raw)).infolist() if info.filename == name)


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


def test_finds_nested_class_via_dotted_ambiguous_name():
    # com.example.Outer.Inner is ambiguous: it could name a top-level class
    # Inner in package com.example.Outer, or the nested class Outer$Inner in
    # package com.example. The class file is compiled as the latter; a caller
    # passing the dotted form must still find it.
    raw = make_jar({"com/example/Outer$Inner.class": b"x"})
    assert contains_class(raw, "com.example.Outer.Inner") is True


def test_corrupt_compressed_data_in_nested_jar_raises():
    # Truncated deflate stream: the likeliest real-world corruption, and the
    # one the original except clause did not catch.
    import io
    import zipfile

    inner = make_jar({TARGET: b"x" * 4096})
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("BOOT-INF/lib/broken.jar", inner)
    raw = bytearray(buffer.getvalue())
    # Corrupt the middle of the compressed payload, leaving headers intact.
    raw[60:80] = b"\x00" * 20

    with pytest.raises(MalformedArtifact):
        contains_class(bytes(raw), TARGET)


def test_layout_prefix_match_is_a_prefix_not_a_suffix():
    # A path merely ENDING in the layout prefix must not match. A loose
    # endswith() would pass the other tests while silently matching classes
    # from unrelated vendored trees.
    raw = make_jar({"vendor/BOOT-INF/classes/com/example/App.class": b"x"})
    assert contains_class(raw, "com/example/App.class") is False


def test_candidate_class_paths_expands_every_plausible_nested_class_split():
    # M29's rationale: candidate_class_paths had zero direct test coverage —
    # exercised only indirectly through contains_class.
    assert candidate_class_paths("com.example.Service") == (
        "com/example/Service.class",
        "com/example$Service.class",
        "com$example$Service.class",
    )


def test_candidate_class_paths_is_unambiguous_for_internal_form():
    assert candidate_class_paths("com/example/Service.class") == ("com/example/Service.class",)


def test_collect_class_paths_normalizes_a_hostile_target():
    # M3: every other test here passes an already-canonical target, so only
    # the entry side of normalize_entry_name was pinned. A caller is not
    # obligated to pre-canonicalise its own targets before calling
    # collect_class_paths — dropping normalize_entry_name on the target side
    # would leave this hostile-but-legal target unmatched against a
    # perfectly ordinary archive entry.
    raw = make_jar({TARGET: b"x"})
    hostile_target = f"./{TARGET}"
    assert collect_class_paths(raw, {hostile_target}) == {hostile_target}


def test_finds_class_in_uppercase_named_nested_archive_outside_a_library_directory():
    # M8: outside a BOOT-INF/lib/ or WEB-INF/lib/ directory, nested-archive
    # detection still relies on a suffix test; it must not be case-sensitive.
    lib = make_jar({TARGET: b"x"})
    raw = make_jar({"vendor/NESTED.JAR": lib})
    assert contains_class(raw, TARGET) is True


def test_finds_class_present_only_under_a_multi_release_override():
    # Multi-Release: true means a class only present under
    # META-INF/versions/N/ loads on any Java 9+ JVM exactly as an unversioned
    # copy would. A presence check that only compares the bare path
    # manufactures Tier 1 proof out of packaging, not out of absence.
    raw = make_jar({f"META-INF/versions/17/{TARGET}": b"x"})
    assert contains_class(raw, TARGET) is True


def test_finds_multi_release_override_inside_a_bundled_library():
    lib = make_jar({f"META-INF/versions/17/{TARGET}": b"x"})
    raw = make_spring_boot_jar(app_classes={}, libraries={"commons-text-1.9.jar": lib})
    assert contains_class(raw, TARGET) is True


def test_finds_multi_release_override_of_a_layout_prefixed_class():
    # F3: the layout-prefix strip and the multi-release strip must compose.
    # Each applied only to the ORIGINAL name (independently of the other)
    # matches neither pattern on this path — Spring Boot 3's nested JarFile
    # honours multi-release, so a versioned override of a BOOT-INF/classes/
    # entry is plausibly loadable and must be found.
    raw = make_jar({"META-INF/versions/9/BOOT-INF/classes/org/x/Y.class": b"x"})
    assert contains_class(raw, "org/x/Y.class") is True


def test_finds_multi_release_override_composed_the_other_way_around():
    # The reverse nesting of the same two prefixes — the strips must compose
    # regardless of which pattern is textually "outer" in the entry name.
    raw = make_jar({"BOOT-INF/classes/META-INF/versions/9/org/x/Y.class": b"x"})
    assert contains_class(raw, "org/x/Y.class") is True


@pytest.mark.parametrize(
    "failure",
    [
        zipfile.BadZipFile("corrupt central directory"),
        zlib.error("Error -3 while decompressing data: invalid distance too far back"),
        RuntimeError("File is encrypted, password required for extraction"),
        NotImplementedError("compression type 99 (AES) is not supported"),
        EOFError("Compressed file ended before the end-of-stream marker was reached"),
        OSError("input/output error"),
    ],
    ids=lambda failure: type(failure).__name__,
)
def test_every_nested_read_failure_becomes_malformed_artifact(failure, monkeypatch):
    """The documented contract: a read failure is always MalformedArtifact.

    Callers are written as `except MalformedArtifact: route_to_human_review()`.
    An untyped exception escaping instead crashes the pipeline rather than
    degrading to review — and the caller can no longer tell "could not read"
    from any other bug. Each of these is a failure zipfile raises in the wild:
    truncated deflate streams, password-protected entries, and unsupported
    compression methods all occur in real artifact stores.
    """
    raw = make_spring_boot_jar(app_classes={}, libraries={"dep.jar": make_jar({})})

    def failing_read(self, name, pwd=None):
        raise failure

    monkeypatch.setattr(zipfile.ZipFile, "read", failing_read)

    with pytest.raises(MalformedArtifact):
        contains_class(raw, TARGET)


def test_duplicate_boot_inf_lib_entry_raises_rather_than_reporting_absence():
    # N3: two central-directory records both named BOOT-INF/lib/commons-text.jar,
    # the first holding the vulnerable class and the second a benign decoy.
    # Which occurrence a JVM classloader would resolve between two
    # identically-named entries is implementation-defined, so a False here
    # would be manufactured proof, not Tier 1 evidence — see the module
    # docstring. Must raise instead of silently searching only one occurrence.
    vulnerable = make_jar({TARGET: b"y"})
    decoy = make_jar({})
    name = "BOOT-INF/lib/commons-text.jar"
    raw = make_jar_with_duplicate_entries([(name, vulnerable), (name, decoy)])
    assert _raw_entry_count(raw, name) == 2, "test setup must genuinely duplicate the entry"

    with pytest.raises(MalformedArtifact, match=re.escape(name)):
        contains_class(raw, TARGET)


def test_duplicate_web_inf_lib_entry_raises_rather_than_reporting_absence():
    # Same as above, for the WAR library prefix.
    vulnerable = make_jar({TARGET: b"y"})
    decoy = make_jar({})
    name = "WEB-INF/lib/commons-text.jar"
    raw = make_jar_with_duplicate_entries([(name, vulnerable), (name, decoy)])
    assert _raw_entry_count(raw, name) == 2, "test setup must genuinely duplicate the entry"

    with pytest.raises(MalformedArtifact, match=re.escape(name)):
        contains_class(raw, TARGET)


def test_duplicate_nested_archive_outside_library_directory_raises():
    # Not every nested archive lives under BOOT-INF/lib or WEB-INF/lib — an
    # EAR module, for instance, is a nested JAR at an arbitrary path. That
    # recursion path reads the entry by its raw name (zipfile.ZipFile.read),
    # which resolves a duplicated name to whichever occurrence the central
    # directory lists last — so, unlike the library-directory case, this one
    # silently searches only the decoy today. It must raise instead.
    vulnerable = make_jar({TARGET: b"y"})
    decoy = make_jar({})
    name = "vendor/nested.jar"
    raw = make_jar_with_duplicate_entries([(name, vulnerable), (name, decoy)])
    assert _raw_entry_count(raw, name) == 2, "test setup must genuinely duplicate the entry"

    with pytest.raises(MalformedArtifact, match=re.escape(name)):
        contains_class(raw, TARGET)


def test_duplicate_meta_inf_license_entries_do_not_raise():
    # Shaded and shadowed JARs routinely carry duplicate META-INF/LICENSE
    # entries from merged dependencies. Nothing in the presence walk ever
    # reads one of these by name — they are not in a library directory and
    # are not named like an archive — so a duplicate here cannot hide a
    # class and must not make an otherwise legitimate shaded-JAR shape
    # unanalysable.
    name = "META-INF/LICENSE"
    raw = make_jar_with_duplicate_entries(
        [
            (TARGET, b"y"),
            (name, b"Apache License 2.0 (from dep A)"),
            (name, b"Apache License 2.0 (from dep B)"),
        ]
    )
    assert _raw_entry_count(raw, name) == 2, "test setup must genuinely duplicate the entry"

    assert contains_class(raw, TARGET) is True


def test_single_occurrence_library_entry_is_unaffected_by_duplicate_guard():
    # The ordinary case: one entry, one name, nothing duplicated anywhere in
    # the archive. The new guard must not fire on it.
    lib = make_jar({TARGET: b"y"})
    raw = make_spring_boot_jar(app_classes={}, libraries={"commons-text-1.9.jar": lib})
    assert contains_class(raw, TARGET) is True


def test_duplicate_target_class_name_is_still_matched_without_reading():
    # The presence walk's matching test does NOT need this guard: it iterates
    # every entry via infolist() and compares names, so it sees both
    # occurrences of a duplicated name regardless of which one zipfile.read()
    # would resolve to. A duplicated target class must therefore still be
    # found, not raise.
    name = TARGET
    raw = make_jar_with_duplicate_entries([(name, b"first-copy"), (name, b"second-copy")])
    assert _raw_entry_count(raw, name) == 2, "test setup must genuinely duplicate the entry"

    assert contains_class(raw, TARGET) is True
