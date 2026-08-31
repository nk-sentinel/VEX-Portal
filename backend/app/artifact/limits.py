"""Resource bounds for untrusted archives.

The artifact under analysis is supplied by the team requesting the
determination. A hostile or merely broken archive must not be able to exhaust
memory or wedge a worker, so every traversal is bounded before it reads.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Limits:
    """Bounds applied while walking an archive."""

    #: Total uncompressed bytes read from one artifact.
    max_total_uncompressed: int

    #: Largest single entry that will be read.
    max_entry_size: int

    #: Most entries that will be visited.
    max_entries: int

    #: Largest uncompressed:compressed ratio tolerated for one entry. A zip
    #: bomb's defining property is an extreme ratio.
    max_compression_ratio: int


#: Sized for real enterprise fat JARs and container layers with headroom. A
#: 300MB artifact with 20,000 entries is large but ordinary; ten times that is
#: not an application.
DEFAULT_LIMITS = Limits(
    max_total_uncompressed=2 * 1024 * 1024 * 1024,
    max_entry_size=512 * 1024 * 1024,
    max_entries=200_000,
    max_compression_ratio=500,
)
