import pytest
from sqlalchemy.exc import IntegrityError

from app.repos.models import Assessment, AssessmentState, AuditEntry, Finding


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
