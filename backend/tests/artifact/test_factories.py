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
    # CONSTANT_Long claims two constant pool indices despite being one
    # physical entry. Adding it to an otherwise identical file must therefore
    # raise constant_pool_count by 2, not by 1. A parser that assumes 1
    # desynchronises for the rest of the pool and silently stops finding
    # class references.
    without = make_class_file(["com/example/A"])
    with_long = make_class_file(["com/example/A"], with_long_entry=True)

    assert struct.unpack_from(">H", without, 8)[0] == 3
    assert struct.unpack_from(">H", with_long, 8)[0] == 5


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
