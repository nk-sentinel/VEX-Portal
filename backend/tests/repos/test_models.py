from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, StatementError

from app.domain.determination import State
from app.repos.models import (
    Assessment,
    AssessmentState,
    AuditEntry,
    Finding,
    FindingOutcome,
    Role,
    User,
)


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


@pytest.mark.asyncio
async def test_timestamps_are_timezone_aware_after_a_round_trip(session):
    # The in-memory object being aware proves nothing; a plain DateTime drops
    # the offset on the way to storage and hands back a naive value.
    a = Assessment(application_id="x", report_id="r", requester="u")
    session.add(a)
    await session.commit()
    session.expunge_all()

    loaded = (await session.execute(select(Assessment))).scalar_one()

    assert loaded.created_at.tzinfo is not None
    assert loaded.created_at.utcoffset() == timedelta(0)


@pytest.mark.asyncio
async def test_a_naive_timestamp_is_rejected_rather_than_assumed_utc(session):
    # Guessing a timezone would make a wrong timestamp look authoritative.
    a = Assessment(application_id="x", report_id="r", requester="u")
    a.created_at = datetime(2026, 9, 1, 12, 0, 0)  # no tzinfo
    session.add(a)
    # SQLAlchemy wraps a bind-param processing error raised during flush in
    # StatementError (see cause chain) rather than letting it propagate
    # as-is; the original ValueError's message still comes through in the
    # wrapped exception's string, which is what `match` checks below.
    with pytest.raises(StatementError, match="naive datetime"):
        await session.commit()


@pytest.mark.asyncio
async def test_a_non_utc_timestamp_is_normalised_not_stored_as_is(session):
    a = Assessment(application_id="x", report_id="r", requester="u")
    a.created_at = datetime(2026, 9, 1, 12, 0, tzinfo=timezone(timedelta(hours=8)))
    session.add(a)
    await session.commit()
    session.expunge_all()

    loaded = (await session.execute(select(Assessment))).scalar_one()
    assert loaded.created_at.utcoffset() == timedelta(0)
    assert loaded.created_at.hour == 4  # 12:00+08:00 is 04:00 UTC


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


@pytest.mark.asyncio
async def test_user_roles_round_trip_through_persistence(session):
    user = User(
        username="alice",
        password_hash="argon2-hash-placeholder",
        roles_json=[Role.REVIEWER.value, Role.APPROVER.value],
    )
    session.add(user)
    await session.commit()
    session.expunge_all()

    loaded = (await session.execute(select(User).where(User.username == "alice"))).scalar_one()

    assert frozenset(Role(value) for value in loaded.roles_json) == frozenset(
        {Role.REVIEWER, Role.APPROVER}
    )


@pytest.mark.asyncio
async def test_username_is_unique(session):
    session.add(User(username="alice", password_hash="h1", roles_json=[]))
    session.add(User(username="alice", password_hash="h2", roles_json=[]))
    with pytest.raises(IntegrityError):
        await session.flush()


@pytest.mark.asyncio
async def test_user_password_hash_is_excluded_from_repr(session):
    # MappedAsDataclass would otherwise include every column in __repr__ by
    # default; password_hash is marked repr=False for exactly this reason.
    user = User(username="alice", password_hash="super-secret-hash-value", roles_json=[])
    assert "super-secret-hash-value" not in repr(user)
