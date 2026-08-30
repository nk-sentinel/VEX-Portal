import hashlib

import pytest

from app.artifact.errors import MalformedArtifact
from app.artifact.inventory import Layout, inspect_archive
from tests.artifact.factories import make_jar, make_spring_boot_jar, make_war


def test_detects_spring_boot_layout():
    raw = make_spring_boot_jar(app_classes={"com/example/App.class": b"x"}, libraries={})
    assert inspect_archive(raw).layout is Layout.SPRING_BOOT_FAT


def test_detects_war_layout():
    raw = make_war(app_classes={"com/example/App.class": b"x"}, libraries={})
    assert inspect_archive(raw).layout is Layout.WAR


def test_detects_plain_jar_layout():
    raw = make_jar({"com/example/App.class": b"x"})
    assert inspect_archive(raw).layout is Layout.PLAIN_JAR


def test_hashes_bundled_libraries():
    lib = make_jar({"org/apache/commons/text/StringSubstitutor.class": b"y"})
    raw = make_spring_boot_jar(app_classes={}, libraries={"commons-text-1.9.jar": lib})

    inventory = inspect_archive(raw)

    assert len(inventory.libraries) == 1
    library = inventory.libraries[0]
    assert library.name == "commons-text-1.9.jar"
    assert library.path == "BOOT-INF/lib/commons-text-1.9.jar"
    assert library.sha1 == hashlib.sha1(lib).hexdigest()
    assert library.sha256 == hashlib.sha256(lib).hexdigest()
    assert library.size == len(lib)


def test_collects_application_classes_stripped_of_layout_prefix():
    raw = make_spring_boot_jar(
        app_classes={"com/example/App.class": b"x", "com/example/Other.class": b"y"},
        libraries={"lib.jar": make_jar({})},
    )
    inventory = inspect_archive(raw)
    assert set(inventory.app_classes) == {"com/example/App.class", "com/example/Other.class"}


def test_library_classes_are_not_counted_as_application_classes():
    # A library referencing a vulnerable class says nothing about whether the
    # application does. Only the application's own bytecode is Tier 2 evidence.
    lib = make_jar({"org/thirdparty/Internal.class": b"y"})
    raw = make_spring_boot_jar(
        app_classes={"com/example/App.class": b"x"}, libraries={"l.jar": lib}
    )
    assert set(inspect_archive(raw).app_classes) == {"com/example/App.class"}


def test_reads_embedded_git_properties():
    raw = make_spring_boot_jar(
        app_classes={},
        libraries={},
        git_properties={
            "git.commit.id.full": "4a9f1c2e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39",
            "git.branch": "release/1.14",
            "git.remote.origin.url": "https://bitbucket.example/scm/pay/payments-api.git",
        },
    )
    inventory = inspect_archive(raw)
    assert inventory.commit_sha() == "4a9f1c2e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39"
    assert inventory.repository_url() == "https://bitbucket.example/scm/pay/payments-api.git"


def test_missing_git_properties_yields_none():
    raw = make_jar({"com/example/App.class": b"x"})
    inventory = inspect_archive(raw)
    assert inventory.commit_sha() is None
    assert inventory.repository_url() is None


def test_library_sha1s_maps_hash_to_name():
    lib = make_jar({})
    raw = make_spring_boot_jar(app_classes={}, libraries={"commons-text-1.9.jar": lib})
    assert inspect_archive(raw).library_sha1s() == {
        hashlib.sha1(lib).hexdigest(): "commons-text-1.9.jar"
    }


def test_rejects_input_that_is_not_an_archive():
    with pytest.raises(MalformedArtifact):
        inspect_archive(b"not a zip at all")
