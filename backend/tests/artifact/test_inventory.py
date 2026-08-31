import hashlib
import io
import re
import warnings
import zipfile
import zlib

import pytest

from app.artifact.errors import MalformedArtifact
from app.artifact.inventory import Layout, inspect_archive
from tests.artifact.factories import (
    make_jar,
    make_jar_with_duplicate_entries,
    make_spring_boot_jar,
    make_war,
)

TARGET_CLASS = "org/apache/commons/text/StringSubstitutor.class"


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
def test_library_read_failure_raises_rather_than_hashing_empty_bytes(failure, monkeypatch):
    # M13: a mutant that swallows the read failure in _read_entry and returns
    # b"" instead of raising would silently hash the empty string into
    # provenance on the library path rather than reporting "could not read".
    raw = make_spring_boot_jar(app_classes={}, libraries={"dep.jar": make_jar({})})

    def failing_read(self, name, pwd=None):
        raise failure

    monkeypatch.setattr(zipfile.ZipFile, "read", failing_read)

    with pytest.raises(MalformedArtifact):
        inspect_archive(raw)


def test_rejects_input_that_is_not_an_archive():
    with pytest.raises(MalformedArtifact):
        inspect_archive(b"not a zip at all")


def test_spring_boot_layout_wins_when_both_prefixes_are_present():
    # Spring Boot ships fat WARs, so an archive can carry both prefixes. The
    # reported layout label still prefers SPRING_BOOT_FAT in that case (see
    # _detect_layout) — but, unlike before the F1 fix, that label no longer
    # decides what gets collected: REWORKED from asserting that only the
    # "winning" layout's classes were collected (BOOT-INF/classes/App.class)
    # and WEB-INF/classes/Legacy.class was silently dropped. That exclusivity
    # was the defect: a decoy under one prefix could make genuine code under
    # the other vanish from app_classes entirely. Collection is now a union
    # of every known class prefix, so both are present. BOOT-INF/lib/dep.jar
    # must still be classified as a library, not application code, regardless
    # of which prefix "won" for reporting purposes.
    raw = make_jar(
        {
            "BOOT-INF/classes/com/example/App.class": b"x",
            "BOOT-INF/lib/dep.jar": make_jar({}),
            "WEB-INF/web.xml": b"<web-app/>",
            "WEB-INF/classes/com/example/Legacy.class": b"y",
        }
    )
    inventory = inspect_archive(raw)
    assert inventory.layout is Layout.SPRING_BOOT_FAT
    assert set(inventory.app_classes) == {"com/example/App.class", "com/example/Legacy.class"}
    assert [library.path for library in inventory.libraries] == ["BOOT-INF/lib/dep.jar"]


def test_multi_release_classes_are_application_code():
    raw = make_jar(
        {
            "com/example/App.class": b"x",
            "META-INF/versions/17/com/example/App.class": b"y",
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
        }
    )
    app_classes = inspect_archive(raw).app_classes
    assert "com/example/App.class" in app_classes
    assert "META-INF/versions/17/com/example/App.class" in app_classes
    assert "META-INF/MANIFEST.MF" not in app_classes


def test_canonical_git_properties_wins_regardless_of_archive_order():
    canonical = b"git.commit.id.full=aaaaaaa\n"
    module = b"git.commit.id.full=bbbbbbb\n"
    for entries in (
        {"BOOT-INF/classes/git.properties": canonical,
         "BOOT-INF/classes/sub/module/git.properties": module},
        {"BOOT-INF/classes/sub/module/git.properties": module,
         "BOOT-INF/classes/git.properties": canonical},
    ):
        assert inspect_archive(make_jar(entries)).commit_sha() == "aaaaaaa"


def test_boot_inf_git_properties_beats_web_inf_regardless_of_archive_order():
    # N4: more than one canonical path can be present at once — a Boot fat
    # WAR carries both BOOT-INF/ and WEB-INF/. Precedence must be decided by
    # an explicit, documented rule (BOOT-INF/classes/ first), never by which
    # one the ZIP happens to list last.
    real = b"git.commit.id.full=" + b"a" * 40 + b"\n"
    decoy = b"git.commit.id.full=" + b"b" * 40 + b"\n"
    for entries in (
        {
            "BOOT-INF/classes/git.properties": real,
            "WEB-INF/classes/git.properties": decoy,
        },
        {
            "WEB-INF/classes/git.properties": decoy,
            "BOOT-INF/classes/git.properties": real,
        },
    ):
        inventory = inspect_archive(make_jar(entries))
        assert inventory.commit_sha() == "a" * 40


def test_web_inf_git_properties_beats_root_regardless_of_archive_order():
    real = b"git.commit.id.full=" + b"c" * 40 + b"\n"
    decoy = b"git.commit.id.full=" + b"d" * 40 + b"\n"
    for entries in (
        {"WEB-INF/classes/git.properties": real, "git.properties": decoy},
        {"git.properties": decoy, "WEB-INF/classes/git.properties": real},
    ):
        inventory = inspect_archive(make_jar(entries))
        assert inventory.commit_sha() == "c" * 40


def test_disagreeing_canonical_git_properties_sets_ambiguous_flag():
    # Two canonical files claiming two different commits is a fact a human
    # reviewer should see, not something silently resolved. The precedence
    # rule still picks a value to return — it just must not hide the
    # disagreement.
    higher_precedence = b"git.commit.id.full=" + b"1" * 40 + b"\n"
    lower_precedence = b"git.commit.id.full=" + b"2" * 40 + b"\n"
    inventory = inspect_archive(
        make_jar(
            {
                "BOOT-INF/classes/git.properties": higher_precedence,
                "WEB-INF/classes/git.properties": lower_precedence,
            }
        )
    )
    assert inventory.commit_sha() == "1" * 40
    assert inventory.git_properties_ambiguous is True


def test_agreeing_canonical_git_properties_does_not_set_ambiguous_flag():
    same = b"git.commit.id.full=" + b"3" * 40 + b"\n"
    inventory = inspect_archive(
        make_jar(
            {
                "BOOT-INF/classes/git.properties": same,
                "WEB-INF/classes/git.properties": same,
            }
        )
    )
    assert inventory.commit_sha() == "3" * 40
    assert inventory.git_properties_ambiguous is False


def test_single_canonical_git_properties_leaves_ambiguous_flag_unset():
    # Regression pin: the common case (exactly one canonical git.properties)
    # must behave exactly as before the N4 fix.
    raw = make_spring_boot_jar(
        app_classes={},
        libraries={},
        git_properties={"git.commit.id.full": "e" * 40},
    )
    inventory = inspect_archive(raw)
    assert inventory.commit_sha() == "e" * 40
    assert inventory.git_properties_ambiguous is False


def test_disagreement_via_commit_id_fallback_key_sets_ambiguous_flag():
    # The disagreement check must resolve each candidate file's commit the
    # same way commit_sha() would (walking the git.commit.id.full ->
    # git.commit.id -> git.commit.id.abbrev fallback chain), not compare the
    # raw git.commit.id.full key alone — otherwise a disagreement expressed
    # only through git.commit.id is invisible even though commit_sha() would
    # actually return a different value for each file.
    higher_precedence = b"git.commit.id=" + b"1" * 40 + b"\n"
    lower_precedence = b"git.commit.id=" + b"2" * 40 + b"\n"
    inventory = inspect_archive(
        make_jar(
            {
                "BOOT-INF/classes/git.properties": higher_precedence,
                "WEB-INF/classes/git.properties": lower_precedence,
            }
        )
    )
    assert inventory.commit_sha() == "1" * 40
    assert inventory.git_properties_ambiguous is True


def test_disagreement_via_commit_id_abbrev_fallback_key_sets_ambiguous_flag():
    higher_precedence = b"git.commit.id.abbrev=aaa1111\n"
    lower_precedence = b"git.commit.id.abbrev=bbb2222\n"
    inventory = inspect_archive(
        make_jar(
            {
                "BOOT-INF/classes/git.properties": higher_precedence,
                "WEB-INF/classes/git.properties": lower_precedence,
            }
        )
    )
    assert inventory.commit_sha() == "aaa1111"
    assert inventory.git_properties_ambiguous is True


def test_same_commit_expressed_through_different_keys_does_not_set_ambiguous_flag():
    # Same commit, stated two different ways (one file uses the .full key,
    # the other the short key) — not a disagreement.
    full_key = b"git.commit.id.full=" + b"3" * 40 + b"\n"
    short_key = b"git.commit.id=" + b"3" * 40 + b"\n"
    inventory = inspect_archive(
        make_jar(
            {
                "BOOT-INF/classes/git.properties": full_key,
                "WEB-INF/classes/git.properties": short_key,
            }
        )
    )
    assert inventory.commit_sha() == "3" * 40
    assert inventory.git_properties_ambiguous is False


def test_file_with_no_commit_key_does_not_make_the_other_ambiguous():
    # A file that says nothing about the commit carries no opinion — it
    # cannot disagree with the file that does.
    has_commit = b"git.commit.id.full=" + b"4" * 40 + b"\n"
    no_commit_key = b"git.branch=main\n"
    inventory = inspect_archive(
        make_jar(
            {
                "BOOT-INF/classes/git.properties": has_commit,
                "WEB-INF/classes/git.properties": no_commit_key,
            }
        )
    )
    assert inventory.commit_sha() == "4" * 40
    assert inventory.git_properties_ambiguous is False


def test_disagreeing_repository_url_sets_ambiguous_flag():
    higher_precedence = b"git.remote.origin.url=https://example.test/real.git\n"
    lower_precedence = b"git.remote.origin.url=https://example.test/decoy.git\n"
    inventory = inspect_archive(
        make_jar(
            {
                "BOOT-INF/classes/git.properties": higher_precedence,
                "WEB-INF/classes/git.properties": lower_precedence,
            }
        )
    )
    assert inventory.repository_url() == "https://example.test/real.git"
    assert inventory.git_properties_ambiguous is True


def test_non_jar_named_library_entry_is_counted_and_hashed():
    # Spring Boot puts every non-directory entry under BOOT-INF/lib/ on the
    # classpath regardless of extension. Filtering on ".jar" here left an
    # entry like this fully loadable by the JVM but invisible to provenance.
    payload = make_jar({"org/example/Thing.class": b"y"})
    raw = make_jar(
        {
            "BOOT-INF/classes/com/example/App.class": b"x",
            "BOOT-INF/lib/commons-text-1.9.zip": payload,
        }
    )
    inventory = inspect_archive(raw)
    assert len(inventory.libraries) == 1
    library = inventory.libraries[0]
    assert library.name == "commons-text-1.9.zip"
    assert library.path == "BOOT-INF/lib/commons-text-1.9.zip"
    assert library.sha1 == hashlib.sha1(payload).hexdigest()


def test_uppercase_named_library_entry_is_counted_despite_case():
    # A case-sensitive ".jar" test made EVIL.JAR provenance-invisible even
    # though presence.py's suffix test already lowercases and would recurse
    # into it — the two halves of the defence disagreed with each other.
    payload = make_jar({})
    raw = make_jar(
        {"BOOT-INF/classes/com/example/App.class": b"x", "BOOT-INF/lib/EVIL.JAR": payload}
    )
    inventory = inspect_archive(raw)
    assert len(inventory.libraries) == 1
    assert inventory.libraries[0].name == "EVIL.JAR"
    assert inventory.libraries[0].sha1 == hashlib.sha1(payload).hexdigest()


def test_duplicate_application_class_entry_raises():
    # Which entry a JVM's classloader picks between two identically-named
    # entries is implementation-defined. Silently keeping "last wins" would
    # scan bytecode that might not be what actually runs, while still
    # reporting the scan as having examined everything.
    # Built by hand so the ZIP genuinely carries the same name twice — a dict
    # of entries can only hold one payload per key. zipfile warns on this by
    # design; the warning is not the point of the test.
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("com/example/App.class", b"first-copy")
            zf.writestr("com/example/App.class", b"second-copy")
    with pytest.raises(MalformedArtifact, match="com/example/App.class"):
        inspect_archive(buffer.getvalue())


def test_empty_directory_entry_does_not_flip_a_plain_jar_to_spring_boot_layout():
    # A zero-byte BOOT-INF/classes/ entry is inert to the JVM and asserts
    # nothing about how the artifact is packaged, so it must not flip the
    # reported layout label to SPRING_BOOT_FAT. Since the F1 fix, the label
    # is purely informational and no longer gates collection either way —
    # see test_content_bearing_decoy_* in test_security.py for the case that
    # actually mattered: a decoy with REAL content.
    raw = make_jar({"BOOT-INF/classes/": b"", "com/example/App.class": b"x"})
    inventory = inspect_archive(raw)
    assert inventory.layout is Layout.PLAIN_JAR
    assert "com/example/App.class" in inventory.app_classes


def test_application_classes_are_collected_from_every_known_prefix_as_a_union():
    # F1: collection must never depend on which single layout was detected.
    raw = make_jar(
        {
            "BOOT-INF/classes/com/example/App.class": b"x",
            "WEB-INF/classes/com/example/Legacy.class": b"y",
            "com/example/RootLevel.class": b"z",
        }
    )
    inventory = inspect_archive(raw)
    assert set(inventory.app_classes) == {
        "com/example/App.class",
        "com/example/Legacy.class",
        "com/example/RootLevel.class",
    }


def test_libraries_are_collected_from_every_known_prefix_as_a_union():
    # F2: a vulnerable library hidden under the "losing" layout's lib prefix
    # must still be hashed, or it never shows up as surplus in provenance.
    boot_lib = make_jar({})
    web_lib = make_jar({"org/example/Thing.class": b"y"})
    raw = make_jar({"BOOT-INF/lib/dep.jar": boot_lib, "WEB-INF/lib/other.jar": web_lib})
    inventory = inspect_archive(raw)
    assert {library.path for library in inventory.libraries} == {
        "BOOT-INF/lib/dep.jar",
        "WEB-INF/lib/other.jar",
    }


def test_cross_prefix_duplicate_key_with_different_content_raises():
    # Two different prefixes strip to the same application class key, with
    # DIFFERENT content. Which copy a JVM's classloader would load is
    # implementation-defined, so this must raise rather than pick one.
    raw = make_jar(
        {
            "BOOT-INF/classes/com/example/App.class": b"real-code",
            "WEB-INF/classes/com/example/App.class": b"different-code",
        }
    )
    with pytest.raises(MalformedArtifact, match="com/example/App.class"):
        inspect_archive(raw)


def test_cross_prefix_duplicate_key_with_identical_content_is_kept_once():
    # Same key from two different prefixes, but the bytes are identical — no
    # ambiguity about what would actually run, so this is deduplicated
    # instead of raising.
    payload = b"identical-bytes"
    raw = make_jar(
        {
            "BOOT-INF/classes/com/example/App.class": payload,
            "WEB-INF/classes/com/example/App.class": payload,
        }
    )
    inventory = inspect_archive(raw)
    assert inventory.app_classes == {"com/example/App.class": payload}


def test_class_under_an_unrecognised_container_subdirectory_is_excluded_and_counted():
    # Defence in depth for F1: a `.class` entry inside a namespace this
    # module recognises as a packaging container (BOOT-INF/) but NOT under
    # either subdirectory it knows how to interpret (classes/ or lib/)
    # matches no collection rule. It must not be silently dropped without a
    # trace — Inventory.excluded_class_count is how scan_references later
    # learns the scan did not see everything.
    raw = make_jar(
        {
            "BOOT-INF/classes/com/example/App.class": b"x",
            "BOOT-INF/oddly-placed/Extra.class": b"y",
        }
    )
    inventory = inspect_archive(raw)
    assert "com/example/App.class" in inventory.app_classes
    assert "BOOT-INF/oddly-placed/Extra.class" not in inventory.app_classes
    assert inventory.excluded_class_count == 1


def test_versioned_copy_of_tooling_is_excluded_like_its_unversioned_twin():
    # A multi-release override of non-application code must not slip past the
    # tooling exclusion. Tooling classes in app_classes would make the
    # reference scan report classes the application never touches.
    raw = make_jar(
        {
            "com/example/App.class": b"x",
            "META-INF/versions/17/com/example/App.class": b"y",
            "org/springframework/boot/loader/Launcher.class": b"z",
            "META-INF/versions/17/org/springframework/boot/loader/Launcher.class": b"w",
        }
    )
    app_classes = inspect_archive(raw).app_classes
    assert "com/example/App.class" in app_classes
    assert "META-INF/versions/17/com/example/App.class" in app_classes
    assert "org/springframework/boot/loader/Launcher.class" not in app_classes
    assert "META-INF/versions/17/org/springframework/boot/loader/Launcher.class" not in app_classes


def _raw_entry_count(raw: bytes, name: str) -> int:
    """How many central-directory records in ``raw`` are named ``name``."""
    return sum(1 for info in zipfile.ZipFile(io.BytesIO(raw)).infolist() if info.filename == name)


def test_duplicate_boot_inf_lib_entry_raises_rather_than_hashing_only_one():
    # N3: two central-directory records both named BOOT-INF/lib/commons-text.jar.
    # zipfile.ZipFile.read(name) — and read_entry_ignoring_declared_size, which
    # this loop calls via the ZipInfo object obtained from infolist() rather
    # than by name — happens to reach the exact occurrence being iterated in
    # THIS process. That is an implementation detail of zipfile, not a
    # guarantee about which occurrence a JVM classloader would resolve between
    # two identically-named entries — that choice is implementation-defined
    # regardless of what this process can read. The honest answer is that we
    # do not know what BOOT-INF/lib/commons-text.jar actually contains, so
    # inspect_archive must refuse to hash it as if we did.
    vulnerable = make_jar({TARGET_CLASS: b"y"})
    decoy = make_jar({})
    name = "BOOT-INF/lib/commons-text.jar"
    raw = make_jar_with_duplicate_entries([(name, vulnerable), (name, decoy)])
    assert _raw_entry_count(raw, name) == 2, "test setup must genuinely duplicate the entry"

    with pytest.raises(MalformedArtifact, match=re.escape(name)):
        inspect_archive(raw)


def test_duplicate_web_inf_lib_entry_raises_rather_than_hashing_only_one():
    # Same as above, for the WAR library prefix — LIBRARY_DIR_PREFIXES has two
    # entries and both must be guarded, not just the Spring Boot one.
    vulnerable = make_jar({TARGET_CLASS: b"y"})
    decoy = make_jar({})
    name = "WEB-INF/lib/commons-text.jar"
    raw = make_jar_with_duplicate_entries([(name, vulnerable), (name, decoy)])
    assert _raw_entry_count(raw, name) == 2, "test setup must genuinely duplicate the entry"

    with pytest.raises(MalformedArtifact, match=re.escape(name)):
        inspect_archive(raw)


def test_duplicate_meta_inf_license_entries_do_not_raise():
    # Shaded and shadowed JARs routinely carry duplicate META-INF/LICENSE (and
    # NOTICE, and services/*) entries from merged dependencies. Nothing in
    # inspect_archive ever reads one of these by name — they are never
    # library-prefix entries, never .class entries, never git.properties — so
    # a duplicate here cannot hide anything and must not make an otherwise
    # legitimate shaded-JAR shape unanalysable.
    name = "META-INF/LICENSE"
    raw = make_jar_with_duplicate_entries(
        [
            ("com/example/App.class", b"x"),
            (name, b"Apache License 2.0 (from dep A)"),
            (name, b"Apache License 2.0 (from dep B)"),
        ]
    )
    assert _raw_entry_count(raw, name) == 2, "test setup must genuinely duplicate the entry"

    inventory = inspect_archive(raw)
    assert "com/example/App.class" in inventory.app_classes


def test_single_occurrence_library_entry_is_unaffected_by_duplicate_guard():
    # The ordinary case: one entry, one name, nothing duplicated anywhere in
    # the archive. The new guard must not fire on it.
    lib = make_jar({TARGET_CLASS: b"y"})
    raw = make_spring_boot_jar(app_classes={}, libraries={"commons-text-1.9.jar": lib})

    inventory = inspect_archive(raw)

    assert len(inventory.libraries) == 1
    assert inventory.libraries[0].sha1 == hashlib.sha1(lib).hexdigest()
