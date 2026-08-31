"""Security tests.

Threat model: the app team requesting a determination controls the artifact the
portal analyses. An artifact crafted so that contains_class() returns False
yields Tier 1 proof and clears a real vulnerability. These tests exist to make
that evasion fail, and to keep a hostile archive from exhausting the host.
"""

import io
import tarfile
import zipfile

import pytest

from app.artifact.errors import ArtifactTooLarge, MalformedArtifact
from app.artifact.image import find_application_archives
from app.artifact.inventory import Layout, inspect_archive
from app.artifact.limits import Limits
from app.artifact.presence import contains_class, normalize_entry_name
from app.artifact.references import scan_references
from tests.artifact.factories import make_class_file

TARGET = "org/apache/commons/text/StringSubstitutor.class"
VULNERABLE = "org/apache/commons/text/StringSubstitutor"


def _zip_with_raw_names(names: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, payload in names.items():
            zf.writestr(name, payload)
    return buffer.getvalue()


class TestEvasionByEntryNaming:
    """Each of these is an attempt to hide a class from the presence check.

    A False from contains_class clears a finding, so every one of these must
    return True.
    """

    @pytest.mark.parametrize(
        "hidden_name",
        [
            f"./{TARGET}",
            f".//{TARGET}",
            f"BOOT-INF/classes/./{TARGET}",
            f"BOOT-INF/lib/../classes/{TARGET}",
            TARGET.replace("/", "\\"),
            f"/{TARGET}",
        ],
    )
    def test_class_is_found_despite_hostile_entry_name(self, hidden_name: str):
        artifact = _zip_with_raw_names({hidden_name: b"payload"})
        assert contains_class(artifact, TARGET) is True

    def test_normalize_entry_name_collapses_traversal_and_separators(self):
        assert normalize_entry_name("./a/./b/../c/d.class") == "a/c/d.class"
        assert normalize_entry_name("a\\b\\c.class") == "a/b/c.class"
        assert normalize_entry_name("/a/b.class") == "a/b.class"

    def test_normalize_entry_name_never_escapes_upward(self):
        # A name that would climb above the archive root is clamped, never
        # returned with leading '..' segments that could match a path outside.
        assert not normalize_entry_name("../../etc/passwd").startswith("..")


class TestDecompressionBombs:
    def test_oversized_declared_entry_is_rejected(self):
        # High-entropy payload so the compression ratio stays near 1:1 and this
        # test isolates the per-entry size cap rather than passing via the
        # ratio check.
        import hashlib

        blob = bytearray()
        seed = b"entry-size-probe"
        while len(blob) < 50_000:
            seed = hashlib.sha256(seed).digest()
            blob.extend(seed)

        tiny = Limits(
            max_total_uncompressed=10**9,
            max_entry_size=5_000,
            max_entries=1000,
            max_compression_ratio=10_000,
        )
        artifact = _zip_with_raw_names({"big.class": bytes(blob)})
        with pytest.raises(ArtifactTooLarge):
            contains_class(artifact, TARGET, limits=tiny)

    def test_total_uncompressed_size_is_capped(self):
        tiny = Limits(
            max_total_uncompressed=10_000,
            max_entry_size=9_000,
            max_entries=1000,
            max_compression_ratio=10_000,
        )
        entries = {f"pkg/C{i}.class": b"\x00" * 4_000 for i in range(10)}
        with pytest.raises(ArtifactTooLarge):
            inspect_archive(_zip_with_raw_names(entries), limits=tiny)

    def test_entry_count_is_capped(self):
        tiny = Limits(
            max_total_uncompressed=10**9,
            max_entry_size=10**9,
            max_entries=5,
            max_compression_ratio=10_000,
        )
        entries = {f"pkg/C{i}.class": b"x" for i in range(50)}
        with pytest.raises(ArtifactTooLarge):
            inspect_archive(_zip_with_raw_names(entries), limits=tiny)

    def test_nested_archive_bomb_is_bounded_by_depth(self):
        # Already covered by max_depth, asserted here so the security surface
        # is documented in one place.
        inner = _zip_with_raw_names({TARGET: b"x"})
        middle = _zip_with_raw_names({"n.jar": inner})
        outer = _zip_with_raw_names({"o.jar": middle})
        with pytest.raises(MalformedArtifact, match="nesting depth"):
            contains_class(outer, TARGET, max_depth=1)


class TestImageLayerSafety:
    def _tar_with(self, build) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tf:
            build(tf)
        return buffer.getvalue()

    def test_symlink_entries_are_ignored(self):
        def build(tf: tarfile.TarFile) -> None:
            link = tarfile.TarInfo("app/evil.jar")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tf.addfile(link)

        assert find_application_archives([self._tar_with(build)]) == []

    def test_device_and_fifo_entries_are_ignored(self):
        def build(tf: tarfile.TarFile) -> None:
            for name, kind in (("app/a.jar", tarfile.CHRTYPE), ("app/b.jar", tarfile.FIFOTYPE)):
                info = tarfile.TarInfo(name)
                info.type = kind
                tf.addfile(info)

        assert find_application_archives([self._tar_with(build)]) == []

    def test_absolute_and_traversing_layer_paths_are_normalised(self):
        payload = _zip_with_raw_names({TARGET: b"x" * 2048})

        def build(tf: tarfile.TarFile) -> None:
            info = tarfile.TarInfo("../../opt/app/application.jar")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))

        found = find_application_archives([self._tar_with(build)])
        assert len(found) == 1
        assert not found[0].path.startswith("..")


class TestTrailingSlashEvasion:
    """ZipInfo.is_dir() trusts the name, not the content.

    An entry named "…/Foo.class/" with a real payload is not a directory. If it
    is skipped as one, a present class reports absent — which is Tier 1 proof
    that clears a live finding.
    """

    def test_class_with_trailing_slash_entry_name_is_still_found(self):
        artifact = _zip_with_raw_names({TARGET + "/": b"payload"})
        assert contains_class(artifact, TARGET) is True

    def test_application_class_with_trailing_slash_survives_inventory(self):
        artifact = _zip_with_raw_names(
            {
                "BOOT-INF/classes/com/example/App.class/": b"x",
                "BOOT-INF/lib/dep.jar": _zip_with_raw_names({"p/C.class": b"c" * 64}),
            }
        )
        assert "com/example/App.class" in inspect_archive(artifact).app_classes

    def test_genuine_empty_directory_entries_are_still_skipped(self):
        # The fix must not start treating real directory entries as classes.
        artifact = _zip_with_raw_names(
            {"BOOT-INF/classes/com/example/": b"", "BOOT-INF/classes/com/example/App.class": b"x"}
        )
        assert sorted(inspect_archive(artifact).app_classes) == ["com/example/App.class"]


class TestNonJarLibraryEntryEvasion:
    """Spring Boot puts every non-directory entry under BOOT-INF/lib/ (or
    WEB-INF/lib/) on the classpath regardless of extension. A presence check
    that only recurses into names ending .jar/.war/.ear misses a renamed or
    extensionless bundled dependency entirely: Tier 1 proof manufactured out
    of a naming choice on content that ships and loads exactly the same.
    """

    def test_class_in_a_non_jar_named_library_entry_is_found(self):
        lib = _zip_with_raw_names({TARGET: b"payload"})
        artifact = _zip_with_raw_names({"BOOT-INF/lib/commons-text-1.9.zip": lib})
        assert contains_class(artifact, TARGET) is True

    def test_class_in_an_uppercase_named_library_entry_is_found(self):
        lib = _zip_with_raw_names({TARGET: b"payload"})
        artifact = _zip_with_raw_names({"BOOT-INF/lib/EVIL.JAR": lib})
        assert contains_class(artifact, TARGET) is True

    def test_non_archive_library_entry_raises_rather_than_being_skipped(self):
        # We cannot distinguish "not an archive" from "a corrupt archive that
        # contained the class". Skipping it would be exactly the
        # failure-reported-as-absence bug this module exists to prevent.
        artifact = _zip_with_raw_names({"BOOT-INF/lib/native-helper": b"not an archive at all"})
        with pytest.raises(MalformedArtifact):
            contains_class(artifact, TARGET)


class TestEmptyDirectoryEntryDoesNotManufactureTier2Conclusiveness:
    """A zero-byte BOOT-INF/classes/ entry is inert to the JVM but, before the
    fix, flipped layout detection on a plain JAR to SPRING_BOOT_FAT and
    emptied app_classes. scan_references then saw zero classes, and
    is_conclusive() was vacuously True at zero classes scanned — a clean
    CODE_NOT_REACHABLE on a class the app demonstrably references.
    """

    def test_reference_scan_survives_a_falsely_flipped_layout(self):
        artifact = _zip_with_raw_names(
            {
                "BOOT-INF/classes/": b"",
                "com/example/App.class": make_class_file([VULNERABLE]),
            }
        )
        inventory = inspect_archive(artifact)
        assert inventory.layout is Layout.PLAIN_JAR

        scan = scan_references(inventory)
        assert scan.classes_scanned == 1
        assert scan.references(VULNERABLE) is True
        assert scan.is_conclusive() is True


class TestEvasionAgainstTheReferenceScan:
    """The same evasion one tier down.

    Hiding a class from app_classes means its constant pool is never scanned,
    so the vulnerable class reads as unreferenced — Tier 2 evidence that
    contributes to clearing a live finding.
    """

    @pytest.mark.parametrize(
        "entry",
        [
            "BOOT-INF/classes/com/example/App.class",
            "./BOOT-INF/classes/com/example/App.class",
            "BOOT-INF/classes/./com/example/App.class",
            "BOOT-INF/lib/../classes/com/example/App.class",
            "BOOT-INF\\classes\\com\\example\\App.class",
        ],
    )
    def test_application_class_is_found_despite_hostile_entry_name(self, entry: str):
        artifact = _zip_with_raw_names(
            {entry: b"x", "BOOT-INF/lib/dep.jar": b"PK\x05\x06" + b"\x00" * 18}
        )
        assert "com/example/App.class" in inspect_archive(artifact).app_classes

    def test_layout_detection_survives_a_hostile_prefix(self):
        artifact = _zip_with_raw_names({"./BOOT-INF/classes/com/example/App.class": b"x"})
        assert inspect_archive(artifact).layout is Layout.SPRING_BOOT_FAT


class TestMalformedInputNeverLeaksUnexpectedExceptions:
    """Every failure must arrive as ArtifactError. An unexpected exception type
    escaping into the service would be handled as an unknown error rather than
    as 'evidence could not be collected', which is a different decision."""

    @pytest.mark.parametrize(
        "payload",
        [
            b"",
            b"PK",
            b"PK\x03\x04",
            b"PK\x03\x04" + b"\xff" * 200,
            b"\x00" * 1024,
            b"\x1f\x8b" + b"\xff" * 100,
        ],
    )
    def test_hostile_bytes_raise_artifact_error(self, payload: bytes):
        from app.artifact.errors import ArtifactError

        for call in (
            lambda: inspect_archive(payload),
            lambda: contains_class(payload, TARGET),
        ):
            with pytest.raises(ArtifactError):
                call()
