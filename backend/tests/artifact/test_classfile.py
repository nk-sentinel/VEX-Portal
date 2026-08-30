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
