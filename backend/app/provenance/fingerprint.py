"""Prove an artifact is the build a scan report describes.

The report lists every component the scanner identified, each with a hash. The
artifact contains bundled libraries, which hash to the same values if it is the
same build. Comparing the two sets establishes provenance using only what is
already in hand — no build metadata, no CI cooperation, no changes to anyone
else's pipeline.

This runs at admission. An artifact that does not match the report is a
different build, and every piece of evidence derived from it would describe
software that was never scanned.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from app.artifact.inventory import Inventory

#: Rebuilds can legitimately differ by a component or two — a timestamped JAR,
#: a reproducibility gap. Below this proportion the artifact is a different
#: build rather than a noisy rebuild.
_DEFAULT_THRESHOLD = 0.95

#: Fewer components than this cannot distinguish a genuine match from a
#: coincidence, so the comparison abstains instead of asserting.
_DEFAULT_MINIMUM_COMPONENTS = 5

#: Proportion of an artifact's components that may be absent from the report
#: before the two are treated as different builds. A scanner does not always
#: identify every bundled JAR, so a small surplus is normal; a large one means
#: the artifact carries content that was never scanned.
_DEFAULT_SURPLUS_TOLERANCE = 0.05


class Verdict(Enum):
    MATCH = "match"
    MISMATCH = "mismatch"

    #: Too little data to assert either way. Not a pass: the caller must treat
    #: this as "provenance unproven" and fall back to other evidence.
    INSUFFICIENT_DATA = "insufficient_data"


@dataclass(frozen=True, slots=True)
class FingerprintResult:
    verdict: Verdict
    matched: int
    report_total: int
    unmatched_report_hashes: list[str]

    #: Components present in the artifact but absent from the report. Surplus
    #: is the direction an attacker controls: retaining a scanned build's
    #: components while adding unscanned ones would otherwise read as a
    #: perfect match.
    unmatched_artifact_hashes: list[str]

    #: Proportion of the artifact's components that the report does not
    #: account for.
    surplus_ratio: float

    ratio: float

    def summary(self) -> str:
        """A one-line description for the reviewer and the audit record."""
        base = (
            f"{self.matched}/{self.report_total} report components found in the artifact "
            f"({self.ratio:.0%})"
        )
        if self.unmatched_artifact_hashes:
            base += (
                f", {len(self.unmatched_artifact_hashes)} artifact components not in the "
                f"report ({self.surplus_ratio:.0%})"
            )
        return f"{base} — {self.verdict.value}"


def compare(
    report_component_sha1s: set[str],
    inventory: Inventory,
    *,
    threshold: float = _DEFAULT_THRESHOLD,
    minimum_components: int = _DEFAULT_MINIMUM_COMPONENTS,
    surplus_tolerance: float = _DEFAULT_SURPLUS_TOLERANCE,
) -> FingerprintResult:
    """Compare the report's component hashes against the artifact's libraries.

    Args:
        report_component_sha1s: SHA-1 hashes of every component in the report.
        inventory: the artifact's inventory.
        threshold: proportion of report components that must be present.
        minimum_components: below this the result is INSUFFICIENT_DATA.
        surplus_tolerance: proportion of the artifact's components that may be
            absent from the report before the artifact is treated as a
            different build.

    Returns:
        The verdict together with the counts a reviewer needs to judge it.
    """
    report_total = len(report_component_sha1s)
    artifact_hashes = set(inventory.library_sha1s())

    matched_hashes = report_component_sha1s & artifact_hashes
    matched = len(matched_hashes)
    unmatched = sorted(report_component_sha1s - artifact_hashes)
    ratio = matched / report_total if report_total else 0.0

    artifact_only = sorted(artifact_hashes - report_component_sha1s)
    surplus_ratio = len(artifact_only) / len(artifact_hashes) if artifact_hashes else 0.0

    if report_total < minimum_components:
        verdict = Verdict.INSUFFICIENT_DATA
    elif ratio >= threshold and surplus_ratio <= surplus_tolerance:
        verdict = Verdict.MATCH
    else:
        verdict = Verdict.MISMATCH

    return FingerprintResult(
        verdict=verdict,
        matched=matched,
        report_total=report_total,
        unmatched_report_hashes=unmatched,
        ratio=ratio,
        unmatched_artifact_hashes=artifact_only,
        surplus_ratio=surplus_ratio,
    )
