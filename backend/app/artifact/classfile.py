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
                    f"unknown tag {tag} at index {index}; cannot determine entry width"
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
