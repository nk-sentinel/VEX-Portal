import struct

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


def test_double_entry_does_not_desynchronise_the_pool():
    # CONSTANT_Double claims two pool indices exactly as CONSTANT_Long does.
    # The factory only exercises Long, so build a Double by hand.
    import struct

    pool = bytearray()
    pool.extend(struct.pack(">B", 6) + b"\x00" * 8)  # Double at index 1, claims 1 and 2
    name = b"com/example/Service"
    pool.extend(struct.pack(">BH", 1, len(name)) + name)  # Utf8 at index 3
    pool.extend(struct.pack(">BH", 7, 3))  # Class at index 4 -> Utf8 at 3
    header = struct.pack(">IHHH", 0xCAFEBABE, 0, 52, 5)
    trailer = struct.pack(">HHHHHHH", 0x0021, 0, 0, 0, 0, 0, 0)

    assert referenced_classes(header + bytes(pool) + trailer) == {"com/example/Service"}


def test_zero_constant_pool_count_raises_rather_than_returning_empty():
    # JVMS 4.1: constant_pool_count's minimum legal value is 1 (an empty
    # pool). 0 is not a legal empty pool, it is a corrupt header. Returning
    # an empty set here would count this class toward classes_scanned as "no
    # references" rather than toward unreadable_classes, silently
    # understating what was actually examined.
    data = bytearray(make_class_file(["com/example/Service"]))
    struct.pack_into(">H", data, 8, 0)
    with pytest.raises(MalformedClassFile):
        referenced_classes(bytes(data))


def test_dangling_class_name_index_raises_rather_than_dropping_the_reference():
    # A Class entry pointing at a non-Utf8 entry must raise. Returning a
    # short set would read downstream as "this class is not referenced".
    import struct

    pool = bytearray()
    pool.extend(struct.pack(">Bi", 3, 42))  # Integer at index 1
    pool.extend(struct.pack(">BH", 7, 1))   # Class at index 2 -> Integer. Invalid.
    header = struct.pack(">IHHH", 0xCAFEBABE, 0, 52, 3)
    trailer = struct.pack(">HHHHHHH", 0x0021, 0, 0, 0, 0, 0, 0)

    with pytest.raises(MalformedClassFile):
        referenced_classes(header + bytes(pool) + trailer)
