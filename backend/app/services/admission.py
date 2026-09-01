"""Decide whether an exploitability-assessment request can be accepted at all.

Three checks, in order, per ``docs/design.md``'s "Assessment flow" step 2:

1. The IQ report is retrievable.
2. The artifact is retrievable (and readable as a JAR/WAR archive).
3. The artifact matches the report — the provenance fingerprint.

Every failure is its own exception type, and every message says what the
requester should do about it — an admission refusal a requester cannot act
on is not much better than a silent failure.

**The third check is a hard stop, not a warning.** An artifact that is not
the build the report describes makes every downstream conclusion — Tier 1/2
evidence, the AI adjudicator's reasoning, the eventual determination —
describe software that was never scanned. ``Verdict.INSUFFICIENT_DATA`` is
deliberately NOT treated as a pass here: per
``app/provenance/fingerprint.py``'s own docstring, too little data to assert
a match is provenance *unproven*, not provenance confirmed, and is refused
for exactly the same reason a confirmed mismatch is.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.adapters.errors import AdapterError
from app.adapters.protocols import ArtifactStore, IqClient, RawReport
from app.artifact.errors import ArtifactTooLarge, MalformedArtifact
from app.artifact.inventory import Inventory, inspect_archive
from app.provenance.fingerprint import FingerprintResult, Verdict, compare


class AdmissionError(Exception):
    """Base for a refused admission request.

    Every subclass's message is written for the requester, not just a
    developer reading a log: it says what happened and what to do next.
    """


class ReportUnavailable(AdmissionError):
    """The IQ report could not be retrieved."""


class ArtifactUnavailable(AdmissionError):
    """The artifact could not be retrieved from JFrog, or could not be read
    as a JAR/WAR archive once retrieved.

    Both collapse to one exception type: from the requester's side, "I
    cannot get your artifact" and "I got bytes back but they are not a
    readable archive" call for the same corrective action — check the
    coordinates and that the artifact is a real build output.
    """


class ProvenanceMismatch(AdmissionError):
    """The artifact does not match the report closely enough to trust that
    it is the build the report describes.

    Includes ``Verdict.INSUFFICIENT_DATA`` — too few components to assert a
    match either way is provenance *unproven*, and is refused for the same
    reason a confirmed mismatch is: nothing downstream may treat an artifact
    as the report's build without evidence that it is.
    """


@dataclass(frozen=True, slots=True)
class AdmittedRequest:
    """Everything evidence collection needs, already fetched and validated
    once at admission so it never has to re-derive provenance from scratch.
    """

    report: RawReport
    artifact: bytes
    inventory: Inventory
    fingerprint: FingerprintResult


async def admit(
    application_id: str,
    report_id: str,
    artifact_coordinates: str,
    *,
    iq: IqClient,
    artifact_store: ArtifactStore,
) -> AdmittedRequest:
    """Run the three admission checks and return everything they proved.

    Args:
        application_id: the Nexus IQ application id the requester named.
        report_id: the Nexus IQ report id the requester named.
        artifact_coordinates: the JFrog Artifactory coordinates (or image
            reference) the requester named.
        iq: the Nexus IQ client.
        artifact_store: the JFrog Artifactory client.

    Raises:
        ReportUnavailable: the IQ report could not be retrieved.
        ArtifactUnavailable: the artifact could not be retrieved, or could
            not be read as a JAR/WAR archive.
        ProvenanceMismatch: the artifact does not match the report.
    """
    try:
        report = await iq.report(application_id, report_id)
    except AdapterError as exc:
        raise ReportUnavailable(
            f"the IQ report {report_id!r} for application {application_id!r} could not be "
            "retrieved. IQ reports purge on a short window — ask the requester to confirm "
            "the report still exists in Nexus IQ, or to raise a fresh scan and resubmit "
            "with the new report URL."
        ) from exc

    try:
        artifact = await artifact_store.fetch(artifact_coordinates)
    except AdapterError as exc:
        raise ArtifactUnavailable(
            f"the artifact at {artifact_coordinates!r} could not be retrieved from JFrog "
            "Artifactory. Ask the requester to confirm the artifact coordinates and that "
            "the artifact has not been deleted or moved."
        ) from exc

    try:
        inventory = inspect_archive(artifact)
    except (MalformedArtifact, ArtifactTooLarge) as exc:
        raise ArtifactUnavailable(
            f"the artifact at {artifact_coordinates!r} could not be read as a JAR/WAR "
            f"archive ({exc}). Ask the requester to confirm the coordinates point at a "
            "valid build artifact, not a directory, a container manifest, or a corrupt "
            "upload."
        ) from exc

    report_component_sha1s = {component.sha1 for component in report.components}
    fingerprint = compare(report_component_sha1s, inventory)
    if fingerprint.verdict is not Verdict.MATCH:
        raise ProvenanceMismatch(
            f"the artifact at {artifact_coordinates!r} does not match report {report_id!r}: "
            f"{fingerprint.summary()}. This artifact cannot be assessed against this report "
            "— ask the requester to confirm they are submitting the exact build that report "
            "scanned, and resubmit both the report and the artifact together."
        )

    return AdmittedRequest(
        report=report, artifact=artifact, inventory=inventory, fingerprint=fingerprint
    )
