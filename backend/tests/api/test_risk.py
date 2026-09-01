"""Tests for `app/api/risk.py` — GET/PUT /api/risk-acceptance."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
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
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/risk-test.db")
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


async def _seed_finding(
    factory: async_sessionmaker[AsyncSession],
    *,
    application_id: str = "app-1",
    cve: str = "CVE-NOFIX",
    outcome: FindingOutcome,
    with_no_fix_rule: bool = False,
) -> str:
    async with factory() as db_session:
        assessment = Assessment(application_id=application_id, report_id="r1", requester="alice")
        db_session.add(assessment)
        await db_session.flush()
        finding = Finding(
            assessment_id=assessment.id,
            cve=cve,
            purl="pkg:maven/x/y@1.0",
            outcome=outcome,
            decided_by="system:alice",
            decided_at=datetime.now(UTC),
        )
        db_session.add(finding)
        await db_session.flush()
        if with_no_fix_rule:
            db_session.add(
                RuleResult(
                    finding_id=finding.id,
                    rule_id="t3-no-fix-available",
                    rule_version="1",
                    verdict=State.UNDER_INVESTIGATION,
                    tier=EvidenceTier.ESCALATION,
                    detail_json={
                        "rule_verdict": "satisfied",
                        "cve": cve,
                        "fix_available": False,
                    },
                )
            )
        await db_session.commit()
        return finding.id


@pytest.mark.asyncio
async def test_the_queue_shows_only_risk_acceptance_required(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="risk", roles=(Role.RISK_MANAGER,))
        risk_id = await _seed_finding(
            factory,
            cve="CVE-NOFIX-1",
            outcome=FindingOutcome.RISK_ACCEPTANCE_REQUIRED,
            with_no_fix_rule=True,
        )
        await _seed_finding(factory, cve="CVE-OK", outcome=FindingOutcome.NOT_AFFECTED)
        await _seed_finding(factory, cve="CVE-BAD", outcome=FindingOutcome.AFFECTED)
        await _seed_finding(factory, cve="CVE-PENDING", outcome=FindingOutcome.NEEDS_REVIEW)

        _login(client, "risk")
        response = client.get("/api/risk-acceptance")

        assert response.status_code == 200, response.text
        rows = response.json()
        assert [row["finding_id"] for row in rows] == [risk_id]
        assert rows[0]["status"] == "awaiting_hand_off"
        assert rows[0]["escalation"]["fix_available"] is False
        assert "waiver" not in response.text.lower()


@pytest.mark.asyncio
async def test_affected_applications_count_spans_applications_sharing_a_cve(
    tmp_path: Path,
) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="risk", roles=(Role.RISK_MANAGER,))
        await _seed_finding(
            factory,
            application_id="app-1",
            cve="CVE-SHARED",
            outcome=FindingOutcome.RISK_ACCEPTANCE_REQUIRED,
        )
        await _seed_finding(
            factory, application_id="app-2", cve="CVE-SHARED", outcome=FindingOutcome.AFFECTED
        )

        _login(client, "risk")
        rows = client.get("/api/risk-acceptance").json()

        assert rows[0]["affected_applications_count"] == 2


@pytest.mark.asyncio
async def test_status_can_be_set_by_a_risk_manager_and_is_audited(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="risk", roles=(Role.RISK_MANAGER,))
        finding_id = await _seed_finding(
            factory, outcome=FindingOutcome.RISK_ACCEPTANCE_REQUIRED
        )

        _login(client, "risk")
        response = client.put(
            f"/api/risk-acceptance/{finding_id}/status", json={"status": "with_risk_manager"}
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "with_risk_manager"
        assert body["status_updated_by"] == "risk"
        assert body["status_updated_at"] is not None


@pytest.mark.asyncio
async def test_an_auditor_can_view_but_not_set_status(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="auditor", roles=(Role.AUDITOR,))
        finding_id = await _seed_finding(
            factory, outcome=FindingOutcome.RISK_ACCEPTANCE_REQUIRED
        )

        _login(client, "auditor")
        assert client.get("/api/risk-acceptance").status_code == 200
        response = client.put(
            f"/api/risk-acceptance/{finding_id}/status", json={"status": "accepted"}
        )
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_view_requires_a_recognised_capability(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="rev", roles=(Role.REVIEWER,))
        _login(client, "rev")
        assert client.get("/api/risk-acceptance").status_code == 403


@pytest.mark.asyncio
async def test_download_package_is_a_self_contained_attachment(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="risk", roles=(Role.RISK_MANAGER,))
        finding_id = await _seed_finding(
            factory,
            cve="CVE-NOFIX-PKG",
            outcome=FindingOutcome.RISK_ACCEPTANCE_REQUIRED,
            with_no_fix_rule=True,
        )

        _login(client, "risk")
        response = client.get(f"/api/risk-acceptance/{finding_id}/package")

        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("application/json")
        assert "attachment" in response.headers.get("content-disposition", "")

        body = response.json()
        assert body["cve"] == "CVE-NOFIX-PKG"
        assert "No fix is available" in body["reason"]
        assert body["hand_off_status"]["status"] == "awaiting_hand_off"
        assert "waiver" not in response.text.lower()


@pytest.mark.asyncio
async def test_package_download_404s_for_a_non_risk_acceptance_finding(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="risk", roles=(Role.RISK_MANAGER,))
        finding_id = await _seed_finding(factory, outcome=FindingOutcome.NOT_AFFECTED)

        _login(client, "risk")
        response = client.get(f"/api/risk-acceptance/{finding_id}/package")

        assert response.status_code == 404
