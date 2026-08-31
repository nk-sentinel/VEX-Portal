"""Recover the application archive from a container image.

For containerised applications the artifact published to the registry is an
image, not a binary. An image is a stack of TAR layers; the application JAR or
WAR is a file inside one of them. Once recovered, every other check in this
package applies to it unchanged.

Layer ordering matters. Layers stack, so a later layer writing the same path
replaces the earlier one, and a deletion appears as an OverlayFS whiteout
marker. Analysing a shadowed copy would assess a build that is not the one
running.

Bomb limits here deliberately omit a per-entry compression-ratio check, unlike
:mod:`app.artifact.presence` and :mod:`app.artifact.inventory`. A ZIP entry
carries its own declared compressed size (``ZipInfo.compress_size``), so a
per-entry ratio can be computed cheaply; a tar member has no such field — a
layer's gzip wrapper compresses the whole stream, not per file, so there is no
per-member compressed size to compare against. Entry count, per-entry declared
size, and a running uncompressed total still bound a hostile layer; the
asymmetry with the zip path is a property of the format, not an oversight.
"""

from __future__ import annotations

import io
import posixpath
import tarfile
from dataclasses import dataclass

from app.artifact.errors import ArtifactTooLarge, MalformedArtifact
from app.artifact.limits import DEFAULT_LIMITS, Limits
from app.artifact.presence import normalize_entry_name

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
    layers: list[bytes],
    *,
    min_size: int = _DEFAULT_MIN_SIZE,
    limits: Limits = DEFAULT_LIMITS,
) -> list[FoundArchive]:
    """Recover candidate application archives from ``layers``.

    Args:
        layers: layer blobs in image order, oldest first. Gzipped or plain TAR.
        min_size: ignore archives smaller than this many bytes.
        limits: resource bounds enforced while walking each layer. See
            :mod:`app.artifact.limits`.

    Returns:
        Surviving archives after layer shadowing and whiteouts are applied,
        ordered by path.

    Raises:
        MalformedArtifact: a layer could not be read as a TAR. Skipping it
            would risk reporting that the application archive is absent when it
            was merely unreadable.
        ArtifactTooLarge: a layer exceeded a resource bound before it could be
            read exhaustively.
    """
    # Path to the newest archive written there. Later layers overwrite.
    surviving: dict[str, FoundArchive] = {}

    for index, blob in enumerate(layers):
        for name, payload in _walk_layer(blob, index, limits):
            base = posixpath.basename(name)

            if base.startswith(_WHITEOUT_PREFIX):
                deleted = posixpath.join(posixpath.dirname(name), base[len(_WHITEOUT_PREFIX) :])
                surviving.pop(deleted, None)
                continue

            if not name.endswith(_ARCHIVE_SUFFIXES) or len(payload) < min_size:
                continue

            surviving[name] = FoundArchive(path=name, layer_index=index, data=payload)

    return [surviving[path] for path in sorted(surviving)]


def _walk_layer(blob: bytes, index: int, limits: Limits) -> list[tuple[str, bytes]]:
    """Return every regular file in one layer as (normalised path, contents).

    Only regular files are returned: ``member.isfile()`` excludes symlinks,
    hardlinks, directories, devices and FIFOs. Following a symlink here would
    turn a layer walk into a file-disclosure primitive, since the link target
    is attacker-controlled and need not point inside the layer at all. Every
    member name is passed through :func:`normalize_entry_name` for the same
    reason entry names are canonicalised in :mod:`app.artifact.presence`: a
    raw name can disagree with the same path written another way, which would
    let a hostile layer defeat shadowing between layers.
    """
    entries_seen = 0
    total_uncompressed = 0
    try:
        # mode "r:*" auto-detects gzip, bzip2, xz, and uncompressed.
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
            entries: list[tuple[str, bytes]] = []
            for member in tf.getmembers():
                entries_seen += 1
                if entries_seen > limits.max_entries:
                    raise ArtifactTooLarge(
                        f"layer {index} has more than {limits.max_entries} entries"
                    )
                if member.size > limits.max_entry_size:
                    raise ArtifactTooLarge(
                        f"layer {index} entry {member.name!r} declares {member.size} bytes, "
                        f"over the {limits.max_entry_size} byte limit"
                    )
                total_uncompressed += member.size
                if total_uncompressed > limits.max_total_uncompressed:
                    raise ArtifactTooLarge(
                        f"layer {index} exceeds {limits.max_total_uncompressed} "
                        "total uncompressed bytes"
                    )
                if not member.isfile():
                    continue
                handle = tf.extractfile(member)
                if handle is None:
                    continue
                entries.append((normalize_entry_name(member.name), handle.read()))
            return entries
    except tarfile.TarError as exc:
        raise MalformedArtifact(f"layer {index} is not a readable tar archive: {exc}") from exc
