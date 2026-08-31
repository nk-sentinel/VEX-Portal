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
from app.artifact.inventory import inspect_archive
from app.artifact.limits import Limits
from app.artifact.presence import contains_class, normalize_entry_name

TARGET = "org/apache/commons/text/StringSubstitutor.class"


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
        tiny = Limits(
            max_total_uncompressed=10_000,
            max_entry_size=5_000,
            max_entries=100,
            max_compression_ratio=200,
        )
        artifact = _zip_with_raw_names({"big.class": b"\x00" * 50_000})
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
