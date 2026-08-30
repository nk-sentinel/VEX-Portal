"""Recover the application archive from a container image.

For containerised applications the artifact published to the registry is an
image, not a binary. An image is a stack of TAR layers; the application JAR or
WAR is a file inside one of them. Once recovered, every other check in this
package applies to it unchanged.

Layer ordering matters. Layers stack, so a later layer writing the same path
replaces the earlier one, and a deletion appears as an OverlayFS whiteout
marker. Analysing a shadowed copy would assess a build that is not the one
running.
"""

from __future__ import annotations

import io
import posixpath
import tarfile
from dataclasses import dataclass

from app.artifact.errors import MalformedArtifact

_ARCHIVE_SUFFIXES = (".jar", ".war", ".ear")
_WHITEOUT_PREFIX = ".wh."

#: Archives smaller than this are JRE stubs, helper JARs, and build tooling
#: rather than the application. The floor is deliberately low: excluding a real
#: application is worse than including a stub, which later checks discard.
_DEFAULT_MIN_SIZE = 1024


@dataclass(frozen=True, slots=True)
class FoundArchive:
    """An application archive recovered from an image layer."""

    path: str
    layer_index: int
    data: bytes


def find_application_archives(
    layers: list[bytes], *, min_size: int = _DEFAULT_MIN_SIZE
) -> list[FoundArchive]:
    """Recover candidate application archives from ``layers``.

    Args:
        layers: layer blobs in image order, oldest first. Gzipped or plain TAR.
        min_size: ignore archives smaller than this many bytes.

    Returns:
        Surviving archives after layer shadowing and whiteouts are applied,
        ordered by path.

    Raises:
        MalformedArtifact: a layer could not be read as a TAR. Skipping it
            would risk reporting that the application archive is absent when it
            was merely unreadable.
    """
    # Path to the newest archive written there. Later layers overwrite.
    surviving: dict[str, FoundArchive] = {}

    for index, blob in enumerate(layers):
        for name, payload in _walk_layer(blob, index):
            base = posixpath.basename(name)

            if base.startswith(_WHITEOUT_PREFIX):
                deleted = posixpath.join(posixpath.dirname(name), base[len(_WHITEOUT_PREFIX) :])
                surviving.pop(deleted, None)
                continue

            if not name.endswith(_ARCHIVE_SUFFIXES) or len(payload) < min_size:
                continue

            surviving[name] = FoundArchive(path=name, layer_index=index, data=payload)

    return [surviving[path] for path in sorted(surviving)]


def _walk_layer(blob: bytes, index: int) -> list[tuple[str, bytes]]:
    """Return every regular file in one layer as (normalised path, contents)."""
    try:
        # mode "r:*" auto-detects gzip, bzip2, xz, and uncompressed.
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
            entries: list[tuple[str, bytes]] = []
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                handle = tf.extractfile(member)
                if handle is None:
                    continue
                entries.append((_normalise(member.name), handle.read()))
            return entries
    except tarfile.TarError as exc:
        raise MalformedArtifact(f"layer {index} is not a readable tar archive: {exc}") from exc


def _normalise(name: str) -> str:
    """Strip the leading ``./`` many tar writers emit, so paths compare equal."""
    return name[2:] if name.startswith("./") else name
