import hashlib

import pytest

from app.artifact.errors import MalformedArtifact
from app.artifact.image import find_application_archives
from tests.artifact.factories import make_jar, make_layer, make_spring_boot_jar


def _incompressible(size: int, seed: bytes = b"vex-portal-test-filler") -> bytes:
    """Deterministic bytes that deflate poorly.

    The size floor in find_application_archives measures the STORED archive,
    and a JAR full of repeated bytes compresses to almost nothing — which is
    how this fixture originally fell under the floor it was meant to clear.
    Hash output has no exploitable structure, so the packaged JAR stays near
    its uncompressed size, the way a real application JAR does.

    ``seed`` distinguishes one caller's filler from another's: two calls with
    the same size but different seeds produce different bytes, so a fixture
    built from this is never accidentally identical to another one.
    """
    out = bytearray()
    while len(out) < size:
        seed = hashlib.sha256(seed).digest()
        out.extend(seed)
    return bytes(out[:size])


APP_JAR = make_spring_boot_jar(
    app_classes={"com/example/App.class": _incompressible(4096)}, libraries={}
)


def test_fixture_clears_the_default_size_floor():
    # Guards the trap this fixture originally fell into: the floor measures the
    # stored archive, and a compressible payload shrinks below it.
    from app.artifact.image import _DEFAULT_MIN_SIZE

    assert len(APP_JAR) > _DEFAULT_MIN_SIZE


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
    old = make_spring_boot_jar(
        app_classes={"com/example/Old.class": _incompressible(4096, b"old-build")}, libraries={}
    )
    layers = [
        make_layer({"app/application.jar": old}),
        make_layer({"app/application.jar": APP_JAR}),
    ]
    found = find_application_archives(layers)
    assert len(found) == 1
    assert found[0].data == APP_JAR
    assert found[0].data != old  # the stale copy must not survive
    assert found[0].layer_index == 1


def test_whiteout_entry_removes_an_earlier_archive():
    # OverlayFS deletions appear as .wh.<name> marker files.
    layers = [
        make_layer({"app/application.jar": APP_JAR}),
        make_layer({"app/.wh.application.jar": b""}),
    ]
    assert find_application_archives(layers) == []


def test_opaque_directory_whiteout_removes_everything_under_the_directory():
    # ".wh..wh..opq" in a directory means every path under it written by an
    # EARLIER layer is deleted — distinct from a single-path ".wh.<name>"
    # whiteout. Without handling it, a deleted archive survives and is
    # returned.
    layers = [
        make_layer({"app/application.jar": APP_JAR, "app/README": b"x" * 10}),
        make_layer({"app/.wh..wh..opq": b""}),
    ]
    assert find_application_archives(layers) == []


def test_opaque_directory_whiteout_does_not_remove_the_same_layers_own_entries():
    # OverlayFS lets a layer opaque a directory and repopulate it in the same
    # step: the deletion only reaches EARLIER layers.
    layers = [
        make_layer({"app/application.jar": APP_JAR}),
        make_layer({"app/.wh..wh..opq": b"", "app/application.jar": APP_JAR}),
    ]
    found = find_application_archives(layers)
    assert [(f.path, f.layer_index) for f in found] == [("app/application.jar", 1)]


def test_opaque_directory_whiteout_does_not_depend_on_entry_order_within_the_layer():
    layers = [
        make_layer({"app/old.jar": APP_JAR}),
        make_layer({"app/new.jar": APP_JAR, "app/.wh..wh..opq": b""}),
    ]
    found = find_application_archives(layers)
    assert [f.path for f in found] == ["app/new.jar"]


def test_uppercase_and_mixed_case_archive_suffixes_are_found():
    # presence.py already lowercases before comparing; this test locks the
    # same rule in on the image-layer side.
    layers = [make_layer({"app/application.JAR": APP_JAR, "app/other.War": APP_JAR})]
    found = find_application_archives(layers)
    assert sorted(f.path for f in found) == ["app/application.JAR", "app/other.War"]


def test_malformed_layer_raises_rather_than_being_skipped():
    with pytest.raises(MalformedArtifact):
        find_application_archives([b"not a tar archive at all"])


def test_corrupt_later_layer_raises_even_after_an_earlier_valid_find():
    # A partial result must not mask a failure. If an early layer yields an
    # archive and a later layer is unreadable, returning the early find would
    # report a complete answer derived from an incomplete walk.
    layers = [make_layer({"app/application.jar": APP_JAR}), b"not a tar archive at all"]
    with pytest.raises(MalformedArtifact):
        find_application_archives(layers)


def test_leading_dot_slash_is_stripped_from_layer_paths():
    # Many tar writers emit "./app/x.jar". The stored path must compare equal
    # to the same path written bare, or layer shadowing silently stops working
    # across writers.
    found = find_application_archives([make_layer({"./app/application.jar": APP_JAR})])
    assert [f.path for f in found] == ["app/application.jar"]


def test_dot_slash_and_bare_paths_are_the_same_entry_across_layers():
    older = make_spring_boot_jar(
        app_classes={"com/example/Old.class": _incompressible(4096, b"old-build")},
        libraries={},
    )
    layers = [
        make_layer({"app/application.jar": older}),
        make_layer({"./app/application.jar": APP_JAR}),
    ]
    found = find_application_archives(layers)
    assert len(found) == 1
    assert found[0].data == APP_JAR


def test_results_are_ordered_by_path():
    second = make_spring_boot_jar(
        app_classes={"com/example/B.class": _incompressible(4096, b"second")}, libraries={}
    )
    layers = [make_layer({"zzz/last.jar": second, "aaa/first.jar": APP_JAR})]
    assert [f.path for f in find_application_archives(layers)] == ["aaa/first.jar", "zzz/last.jar"]
