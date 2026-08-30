import hashlib

import pytest

from app.artifact.errors import MalformedArtifact
from app.artifact.image import find_application_archives
from tests.artifact.factories import make_jar, make_layer, make_spring_boot_jar


def _incompressible(size: int) -> bytes:
    """Deterministic bytes that deflate poorly.

    The size floor in find_application_archives measures the STORED archive,
    and a JAR full of repeated bytes compresses to almost nothing — which is
    how this fixture originally fell under the floor it was meant to clear.
    Hash output has no exploitable structure, so the packaged JAR stays near
    its uncompressed size, the way a real application JAR does.
    """
    out = bytearray()
    seed = b"vex-portal-test-filler"
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
