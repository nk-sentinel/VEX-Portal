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
