"""Tests for `app/api/dashboard.py` — GET /api/dashboard/*.

Every test seeds exact rows and checks the panel's numbers against a manual
count of what was seeded — "dashboard numbers match the underlying rows"
(task-6 brief), pinned directly rather than trusted.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import get_session, make_engine, session_factory
from app.domain.determination import EvidenceTier, State
from app.main import create_app
from app.repos.models import Assessment, Base, Finding, FindingOutcome, Role, RuleResult, User

_PASSWORD = "correct horse battery staple"  # noqa: S105 - test fixture, not a real credential


@asynccontextmanager
async def _client(
    tmp_path: Path,
) -> AsyncIterator[tuple[TestClient, async_sessionmaker[AsyncSession]]]:
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/dashboard-test.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)

    async def _override_get_session() -> AsyncIterator[AsyncSession]:
        async with factory() as db_session:
            yield db_session

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    with TestClient(app) as client:
        yield client, factory

    await engine.dispose()


async def _seed_user(
    factory: async_sessionmaker[AsyncSession], *, username: str, roles: Iterable[Role]
) -> None:
    hasher = PasswordHasher()
    async with factory() as db_session:
        db_session.add(
            User(
                username=username,
                password_hash=hasher.hash(_PASSWORD),
                roles_json=[role.value for role in roles],
            )
        )
        await db_session.commit()


def _login(client: TestClient, username: str) -> None:
    response = client.post("/api/auth/login", json={"username": username, "password": _PASSWORD})
    assert response.status_code == 200, response.text


async def _seed_assessment(
    factory: async_sessionmaker[AsyncSession],
    *,
    application_id: str = "app-1",
    submitted_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> str:
    async with factory() as db_session:
        assessment = Assessment(
            application_id=application_id,
            report_id="r1",
            requester="alice",
            submitted_at=submitted_at or datetime.now(UTC),
            expires_at=expires_at,
        )
        db_session.add(assessment)
        await db_session.commit()
        return assessment.id


async def _seed_finding(
    factory: async_sessionmaker[AsyncSession],
    *,
    assessment_id: str,
    cve: str,
    outcome: FindingOutcome,
    decided_by: str | None = None,
    decided_at: datetime | None = None,
) -> str:
    async with factory() as db_session:
        finding = Finding(
            assessment_id=assessment_id,
            cve=cve,
            purl="pkg:maven/x/y@1.0",
            outcome=outcome,
            decided_by=decided_by,
            decided_at=decided_at,
        )
        db_session.add(finding)
        await db_session.commit()
        return finding.id


async def _seed_rule_result(
    factory: async_sessionmaker[AsyncSession], *, finding_id: str, cve: str
) -> None:
    async with factory() as db_session:
        db_session.add(
            RuleResult(
                finding_id=finding_id,
                rule_id="t1-class-absent",
                rule_version="1",
                verdict=State.NOT_AFFECTED,
                tier=EvidenceTier.PROOF,
                detail_json={"rule_verdict": "satisfied", "cve": cve},
            )
        )
        await db_session.commit()


@pytest.mark.asyncio
async def test_volume_matches_the_seeded_rows(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="auditor", roles=(Role.AUDITOR,))
        a1 = await _seed_assessment(factory, application_id="app-1")
        a2 = await _seed_assessment(factory, application_id="app-2")
        await _seed_finding(
            factory, assessment_id=a1, cve="CVE-1", outcome=FindingOutcome.NOT_AFFECTED
        )
        await _seed_finding(
            factory, assessment_id=a1, cve="CVE-2", outcome=FindingOutcome.AFFECTED
        )
        await _seed_finding(
            factory, assessment_id=a2, cve="CVE-3", outcome=FindingOutcome.NEEDS_REVIEW
        )

        _login(client, "auditor")
        body = client.get("/api/dashboard/volume").json()

        assert body["total_assessments"] == 2
        assert body["total_findings"] == 3
        assert body["findings_by_outcome"] == {
            "not_affected": 1,
            "affected": 1,
            "needs_review": 1,
        }

        scoped = client.get("/api/dashboard/volume", params={"application_id": "app-1"}).json()
        assert scoped["total_assessments"] == 1
        assert scoped["total_findings"] == 2


@pytest.mark.asyncio
async def test_automation_split_distinguishes_system_from_human_decisions(
    tmp_path: Path,
) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="auditor", roles=(Role.AUDITOR,))
        a1 = await _seed_assessment(factory)
        now = datetime.now(UTC)
        await _seed_finding(
            factory,
            assessment_id=a1,
            cve="CVE-AUTO",
            outcome=FindingOutcome.NOT_AFFECTED,
            decided_by="system:alice",
            decided_at=now,
        )
        await _seed_finding(
            factory,
            assessment_id=a1,
            cve="CVE-HUMAN",
            outcome=FindingOutcome.AFFECTED,
            decided_by="bob",
            decided_at=now,
        )
        # Not yet decided — must not be counted either way.
        await _seed_finding(
            factory, assessment_id=a1, cve="CVE-PENDING", outcome=FindingOutcome.NEEDS_REVIEW
        )

        _login(client, "auditor")
        body = client.get("/api/dashboard/automation-split").json()

        assert body["total_decided"] == 2
        assert body["automated"] == 1
        assert body["human_reviewed"] == 1
        assert body["automated_ratio"] == 0.5


@pytest.mark.asyncio
async def test_sla_breaching_count_reflects_overdue_needs_review_findings(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="auditor", roles=(Role.AUDITOR,))
        overdue = await _seed_assessment(
            factory, submitted_at=datetime.now(UTC) - timedelta(hours=48)
        )
        fresh = await _seed_assessment(factory, submitted_at=datetime.now(UTC))
        await _seed_finding(
            factory, assessment_id=overdue, cve="CVE-OLD", outcome=FindingOutcome.NEEDS_REVIEW
        )
        await _seed_finding(
            factory, assessment_id=fresh, cve="CVE-NEW", outcome=FindingOutcome.NEEDS_REVIEW
        )

        _login(client, "auditor")
        body = client.get("/api/dashboard/sla").json()

        assert body["breaching_count"] == 1


@pytest.mark.asyncio
async def test_sla_median_and_p90_reflect_time_to_determination(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="auditor", roles=(Role.AUDITOR,))
        submitted = datetime.now(UTC) - timedelta(hours=10)
        a1 = await _seed_assessment(factory, submitted_at=submitted)
        await _seed_finding(
            factory,
            assessment_id=a1,
            cve="CVE-FAST",
            outcome=FindingOutcome.NOT_AFFECTED,
            decided_by="system:alice",
            decided_at=submitted + timedelta(hours=2),
        )
        await _seed_finding(
            factory,
            assessment_id=a1,
            cve="CVE-SLOW",
            outcome=FindingOutcome.AFFECTED,
            decided_by="bob",
            decided_at=submitted + timedelta(hours=8),
        )

        _login(client, "auditor")
        body = client.get("/api/dashboard/sla").json()

        assert body["sample_size"] == 2
        assert body["median_hours_to_determination"] == pytest.approx(5.0, abs=0.1)


@pytest.mark.asyncio
async def test_agreement_panel_computes_rate_from_rule_results_and_final_outcomes(
    tmp_path: Path,
) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="auditor", roles=(Role.AUDITOR,))
        a1 = await _seed_assessment(factory)
        now = datetime.now(UTC)

        agreed = await _seed_finding(
            factory,
            assessment_id=a1,
            cve="CVE-AGREE",
            outcome=FindingOutcome.NOT_AFFECTED,
            decided_by="system:alice",
            decided_at=now,
        )
        await _seed_rule_result(factory, finding_id=agreed, cve="CVE-AGREE")

        disagreed = await _seed_finding(
            factory,
            assessment_id=a1,
            cve="CVE-DISAGREE",
            outcome=FindingOutcome.AFFECTED,
            decided_by="bob",
            decided_at=now,
        )
        await _seed_rule_result(factory, finding_id=disagreed, cve="CVE-DISAGREE")

        _login(client, "auditor")
        body = client.get("/api/dashboard/agreement").json()

        rule_ids = {row["rule_id"] for row in body["rules"]}
        assert "t1-class-absent" in rule_ids
        assert "t3-kev" not in rule_ids  # Tier 3 excluded — no clearing direction

        row = next(r for r in body["rules"] if r["rule_id"] == "t1-class-absent")
        assert row["volume_30d"] == 2
        assert row["agreement_rate"] == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_outcome_mix_is_grouped_by_application(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="auditor", roles=(Role.AUDITOR,))
        a1 = await _seed_assessment(factory, application_id="app-1")
        a2 = await _seed_assessment(factory, application_id="app-2")
        now = datetime.now(UTC)
        await _seed_finding(
            factory,
            assessment_id=a1,
            cve="CVE-1",
            outcome=FindingOutcome.NOT_AFFECTED,
            decided_by="system:alice",
            decided_at=now,
        )
        await _seed_finding(
            factory,
            assessment_id=a2,
            cve="CVE-2",
            outcome=FindingOutcome.RISK_ACCEPTANCE_REQUIRED,
            decided_by="system:alice",
            decided_at=now,
        )

        _login(client, "auditor")
        body = client.get("/api/dashboard/outcome-mix").json()

        by_app = {row["application_id"]: row for row in body["by_application"]}
        assert by_app["app-1"]["not_affected"] == 1
        assert by_app["app-2"]["risk_acceptance_required"] == 1


@pytest.mark.asyncio
async def test_expiry_panel_counts_lapsing_and_expired(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="auditor", roles=(Role.AUDITOR,))
        now = datetime.now(UTC)
        await _seed_assessment(factory, expires_at=now + timedelta(days=3))  # lapsing
        await _seed_assessment(factory, expires_at=now - timedelta(days=1))  # already expired
        await _seed_assessment(factory, expires_at=now + timedelta(days=20))  # neither
        await _seed_assessment(factory, expires_at=None)  # never determined

        _login(client, "auditor")
        body = client.get("/api/dashboard/expiry").json()

        assert body["lapsing_within_7_days"] == 1
        assert body["already_expired"] == 1


@pytest.mark.asyncio
async def test_dashboard_requires_view_dashboard_capability(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="rev", roles=(Role.REVIEWER,))
        _login(client, "rev")

        for path in (
            "/api/dashboard/volume",
            "/api/dashboard/automation-split",
            "/api/dashboard/sla",
            "/api/dashboard/agreement",
            "/api/dashboard/outcome-mix",
            "/api/dashboard/expiry",
        ):
            assert client.get(path).status_code == 403, path


@pytest.mark.asyncio
async def test_dashboard_without_a_session_is_401(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, _factory):
        assert client.get("/api/dashboard/volume").status_code == 401
