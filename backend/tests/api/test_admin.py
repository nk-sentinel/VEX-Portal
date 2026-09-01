"""Tests for `app/api/admin.py` — GET/PUT /api/admin/rules."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db import get_session, make_engine, session_factory
from app.domain.determination import EvidenceTier, State
from app.main import create_app
from app.repos.models import (
    Assessment,
    AuditEntry,
    Base,
    Finding,
    FindingOutcome,
    Role,
    RuleConfig,
    RuleResult,
    User,
)
from app.rules.registry import PENDING_EVIDENCE

_PASSWORD = "correct horse battery staple"  # noqa: S105 - test fixture, not a real credential


@asynccontextmanager
async def _client(
    tmp_path: Path,
) -> AsyncIterator[tuple[TestClient, async_sessionmaker[AsyncSession]]]:
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/admin-test.db")
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


async def _seed_epss_finding(
    factory: async_sessionmaker[AsyncSession], *, epss: float, decided_days_ago: int = 1
) -> None:
    async with factory() as db_session:
        assessment = Assessment(application_id="app-1", report_id="r1", requester="alice")
        db_session.add(assessment)
        await db_session.flush()
        finding = Finding(
            assessment_id=assessment.id,
            cve="CVE-EPSS",
            purl="pkg:maven/x/y@1.0",
            outcome=FindingOutcome.NEEDS_REVIEW,
            decided_by="system:alice",
            decided_at=datetime.now(UTC) - timedelta(days=decided_days_ago),
        )
        db_session.add(finding)
        await db_session.flush()
        db_session.add(
            RuleResult(
                finding_id=finding.id,
                rule_id="t3-epss",
                rule_version="1",
                verdict=State.UNDER_INVESTIGATION,
                tier=EvidenceTier.ESCALATION,
                detail_json={"rule_verdict": "satisfied", "cve": "CVE-EPSS", "epss": epss},
            )
        )
        await db_session.commit()


# --- GET /api/admin/rules -----------------------------------------------------


@pytest.mark.asyncio
async def test_list_rules_shows_active_and_pending_with_distinct_shapes(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="admin", roles=(Role.ADMIN,))
        _login(client, "admin")

        response = client.get("/api/admin/rules")
        assert response.status_code == 200, response.text
        rows = response.json()
        by_id = {row["rule_id"]: row for row in rows}

        # A Tier 1 rule: toggleable, and the field genuinely present.
        assert by_id["t1-class-absent"]["has_auto_determination_toggle"] is True
        assert "auto_determination_enabled" in by_id["t1-class-absent"]

        # A Tier 3 rule: no toggle field at all — not null, ABSENT.
        assert by_id["t3-kev"]["has_auto_determination_toggle"] is False
        assert "auto_determination_enabled" not in by_id["t3-kev"]

        # Pending-evidence rules are shown, marked unregistered, with a reason.
        for rule_id in PENDING_EVIDENCE:
            if rule_id == "tier3signals.reachable_with_call_path":
                assert rule_id not in by_id  # not a rule id — excluded
                continue
            assert by_id[rule_id]["registered"] is False
            assert by_id[rule_id]["reason"]


@pytest.mark.asyncio
async def test_list_rules_requires_manage_rules_capability(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="rev", roles=(Role.REVIEWER,))
        _login(client, "rev")

        assert client.get("/api/admin/rules").status_code == 403


@pytest.mark.asyncio
async def test_list_rules_without_a_session_is_401(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, _factory):
        assert client.get("/api/admin/rules").status_code == 401


# --- PUT /api/admin/rules/{id} -------------------------------------------------


@pytest.mark.asyncio
async def test_a_tier3_rule_cannot_be_given_a_toggle_even_by_crafting_the_request(
    tmp_path: Path,
) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="admin", roles=(Role.ADMIN,))
        _login(client, "admin")

        response = client.put(
            "/api/admin/rules/t3-kev", json={"auto_determination_enabled": True}
        )
        assert response.status_code == 422

        # No RuleConfig row was created as a side effect of the refusal.
        async with factory() as db_session:
            cfg = await db_session.get(RuleConfig, "t3-kev")
            assert cfg is None


@pytest.mark.asyncio
async def test_a_pending_evidence_rule_cannot_be_given_a_toggle_either(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="admin", roles=(Role.ADMIN,))
        _login(client, "admin")

        # Not even a registered ACTIVE_RULES entry — crafting a request
        # against its id must still be refused, not silently accepted.
        response = client.put(
            "/api/admin/rules/t1-cve-withdrawn", json={"auto_determination_enabled": True}
        )
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_an_unknown_rule_id_is_404(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="admin", roles=(Role.ADMIN,))
        _login(client, "admin")

        response = client.put(
            "/api/admin/rules/not-a-real-rule", json={"agreement_bar": 0.9}
        )
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_toggling_a_tier1_rule_is_persisted_and_audited(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="admin", roles=(Role.ADMIN,))
        _login(client, "admin")

        response = client.put(
            "/api/admin/rules/t1-class-absent", json={"auto_determination_enabled": False}
        )
        assert response.status_code == 200, response.text
        assert response.json()["auto_determination_enabled"] is False

        async with factory() as db_session:
            cfg = await db_session.get(RuleConfig, "t1-class-absent")
            assert cfg is not None
            assert cfg.auto_determination_enabled is False
            assert cfg.updated_by == "admin"

            entries = (await db_session.execute(select(AuditEntry))).scalars().all()
            assert any(
                e.action == "admin.rule_updated" and e.subject_id == "t1-class-absent"
                for e in entries
            )

        listing = client.get("/api/admin/rules").json()
        row = next(r for r in listing if r["rule_id"] == "t1-class-absent")
        assert row["auto_determination_enabled"] is False


@pytest.mark.asyncio
async def test_epss_threshold_change_returns_the_routing_difference_and_is_audited(
    tmp_path: Path,
) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="admin", roles=(Role.ADMIN,))
        # Three findings in the last 30 days with distinct EPSS values.
        # Default hard-block threshold is 0.10; new threshold below is 0.20.
        await _seed_epss_finding(factory, epss=0.05)  # blocked by neither
        await _seed_epss_finding(factory, epss=0.15)  # blocked by old(0.10), not by new(0.20)
        await _seed_epss_finding(factory, epss=0.90)  # blocked by both

        _login(client, "admin")
        response = client.put(
            "/api/admin/rules/t3-epss", json={"epss_hard_block_threshold": 0.20}
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["epss_hard_block_threshold"] == 0.20
        # Only the 0.15 finding crosses from "blocked" to "not blocked".
        assert body["routing_difference_count"] == 1

        async with factory() as db_session:
            entries = (await db_session.execute(select(AuditEntry))).scalars().all()
            assert any(
                e.action == "admin.rule_updated" and e.subject_id == "t3-epss" for e in entries
            )


@pytest.mark.asyncio
async def test_epss_threshold_only_applies_to_the_epss_rule(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="admin", roles=(Role.ADMIN,))
        _login(client, "admin")

        response = client.put(
            "/api/admin/rules/t1-class-absent", json={"epss_hard_block_threshold": 0.5}
        )
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_update_rule_requires_manage_rules_capability(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="auditor", roles=(Role.AUDITOR,))
        _login(client, "auditor")

        response = client.put(
            "/api/admin/rules/t1-class-absent", json={"auto_determination_enabled": False}
        )
        assert response.status_code == 403
