import zipfile
import zlib

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
