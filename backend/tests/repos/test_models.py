import pytest
from sqlalchemy.exc import IntegrityError

from app.domain.determination import State
from app.repos.models import Assessment, AssessmentState, AuditEntry, Finding, FindingOutcome


@pytest.mark.asyncio
async def test_assessment_keys_on_app_and_report_not_on_violation_ids(session):
    # Violation ids change on every re-scan, so keying on them would fragment
    # a case's history across scans.
    a = Assessment(application_id="payments-api", report_id="38ef4d1f", requester="j.doe")
    session.add(a)
    await session.flush()
    assert a.id and a.state is AssessmentState.DRAFT


@pytest.mark.asyncio
async def test_finding_requires_its_assessment(session):
    session.add(Finding(assessment_id="does-not-exist", cve="CVE-2022-42889", purl="pkg:maven/x"))
    with pytest.raises(IntegrityError):
        await session.flush()


@pytest.mark.asyncio
async def test_audit_entries_are_append_only(session):
    entry = AuditEntry(actor="j.doe", action="assessment.submitted", subject_id="ASM-1")
    session.add(entry)
    await session.flush()
    entry.actor = "someone.else"
    with pytest.raises(PermissionError, match="append-only"):
        await session.flush()


@pytest.mark.asyncio
async def test_timestamps_are_generated_in_python_not_by_the_database(session):
    # A dialect-specific server default would tie the schema to SQLite and
    # break the promise that a server database is a connection-string change.
    a = Assessment(application_id="a", report_id="r", requester="u")
    assert a.created_at is not None
    assert a.created_at.tzinfo is not None


def test_finding_outcomes_map_onto_vex_states_without_drift():
    # Two vocabularies at different layers. Nothing stops someone renaming a
    # value on one side, so pin the bridge rather than trusting it.
    assert FindingOutcome.NOT_AFFECTED.to_vex_state() is State.NOT_AFFECTED
    assert FindingOutcome.AFFECTED.to_vex_state() is State.AFFECTED
    assert FindingOutcome.NEEDS_REVIEW.to_vex_state() is State.UNDER_INVESTIGATION
    assert FindingOutcome.NOT_AFFECTED.value == State.NOT_AFFECTED.value
    assert FindingOutcome.AFFECTED.value == State.AFFECTED.value


def test_risk_acceptance_has_no_vex_state_because_it_is_not_a_determination():
    # No fix exists, the app team takes it to their risk manager, and the IQ
    # violation stays open. Exporting it as a VEX state would report a
    # hand-off as a resolution.
    assert FindingOutcome.RISK_ACCEPTANCE_REQUIRED.to_vex_state() is None


def test_every_outcome_is_covered_by_the_mapping():
    # A new outcome added later must be considered here, not silently
    # KeyError at export time.
    for outcome in FindingOutcome:
        outcome.to_vex_state()
