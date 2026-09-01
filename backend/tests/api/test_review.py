"""Tests for `app/api/review.py` — GET /api/review/findings,
GET /api/review/findings/{id}, POST .../recommend, POST .../decide.

Findings/rule-trace/AI-verdict rows are seeded directly against the
database rather than driven through `POST /api/assessments` (already
covered end-to-end in `tests/api/test_assessments.py`) — this suite's job is
the review/commit logic itself, so each case starts from an exact,
deterministic finding state instead of depending on the fake-IQ scenario or
the rule engine's own routing.
"""

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

from app.adapters.protocols import DeterminationOptions, FindingRef
from app.api.deps import get_iq_client_dep
from app.db import get_session, make_engine, session_factory
from app.domain.determination import Confidence, EvidenceTier, Justification, State
from app.main import create_app
from app.repos.models import (
    AiVerdict as AiVerdictRow,
)
from app.repos.models import (
    Assessment,
    AssessmentState,
    AuditEntry,
    Base,
    Finding,
    FindingOutcome,
    IqDeterminationLink,
    Role,
    RuleResult,
    User,
)

_PASSWORD = "correct horse battery staple"  # noqa: S105 - test fixture, not a real credential


class _StubIq:
    """Only `create_determination` is ever reached by `app/api/review.py` —
    every other method is a deliberate stub that fails loudly if called."""

    def __init__(self, *, link_id: str = "application|app-1|link-1") -> None:
        self._link_id = link_id
        self.create_calls: list[tuple[FindingRef, DeterminationOptions]] = []

    async def applications_for_user(self, user_token: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def report(self, application_id: str, report_id: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def vulnerability(self, vuln_id: str, component_purl: str | None):  # pragma: no cover
        raise NotImplementedError

    async def remediation(self, application_id: str, purl: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def source_control(self, application_id: str):  # pragma: no cover - unused
        raise NotImplementedError

    async def create_determination(
        self, finding: FindingRef, options: DeterminationOptions
    ) -> str:
        self.create_calls.append((finding, options))
        return self._link_id

    async def revoke_determination(self, link_id: str) -> None:  # pragma: no cover - unused
        raise NotImplementedError


@asynccontextmanager
async def _client(
    tmp_path: Path, *, iq: _StubIq | None = None
) -> AsyncIterator[tuple[TestClient, async_sessionmaker[AsyncSession]]]:
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/review-test.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)

    async def _override_get_session() -> AsyncIterator[AsyncSession]:
        async with factory() as db_session:
            yield db_session

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session
    app.dependency_overrides[get_iq_client_dep] = lambda: iq or _StubIq()

    with TestClient(app) as client:
        yield client, factory

    await engine.dispose()


async def _seed_user(
    factory: async_sessionmaker[AsyncSession],
    *,
    username: str,
    roles: Iterable[Role],
    password: str = _PASSWORD,
) -> None:
    hasher = PasswordHasher()
    async with factory() as db_session:
        db_session.add(
            User(
                username=username,
                password_hash=hasher.hash(password),
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
    requester: str = "alice",
    application_id: str = "app-1",
    state: AssessmentState = AssessmentState.NEEDS_REVIEW,
    submitted_at: datetime | None = None,
) -> str:
    async with factory() as db_session:
        assessment = Assessment(
            application_id=application_id,
            report_id="report-1",
            requester=requester,
            state=state,
            submitted_at=submitted_at or datetime.now(UTC),
        )
        db_session.add(assessment)
        await db_session.commit()
        return assessment.id


async def _seed_finding(
    factory: async_sessionmaker[AsyncSession],
    *,
    assessment_id: str,
    cve: str = "CVE-2024-0001",
    purl: str = "pkg:maven/x/y@1.0",
    outcome: FindingOutcome | None = FindingOutcome.NEEDS_REVIEW,
    tier: EvidenceTier | None = None,
    justification: Justification | None = None,
    confidence: Confidence | None = None,
    decided_by: str | None = None,
    decided_at: datetime | None = None,
    rule_results: list[dict[str, object]] | None = None,
    ai_verdict: dict[str, object] | None = None,
) -> str:
    async with factory() as db_session:
        finding = Finding(
            assessment_id=assessment_id,
            cve=cve,
            purl=purl,
            outcome=outcome,
            tier=tier,
            justification=justification,
            confidence=confidence,
            decided_by=decided_by,
            decided_at=decided_at,
        )
        db_session.add(finding)
        await db_session.flush()
        for rr in rule_results or []:
            db_session.add(RuleResult(finding_id=finding.id, **rr))
        if ai_verdict is not None:
            db_session.add(AiVerdictRow(finding_id=finding.id, **ai_verdict))
        await db_session.commit()
        return finding.id


_TIER1_CLEAR_RULE = {
    "rule_id": "t1-class-absent",
    "rule_version": "1",
    "verdict": State.NOT_AFFECTED,
    "tier": EvidenceTier.PROOF,
    "detail_json": {"rule_verdict": "satisfied", "cve": "CVE-2024-0001"},
}


# --- Queue filtering -----------------------------------------------------


@pytest.mark.asyncio
async def test_queue_filters_by_state_application_and_assessment(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="rev", roles=(Role.REVIEWER,))
        a1 = await _seed_assessment(factory, application_id="app-1")
        a2 = await _seed_assessment(factory, application_id="app-2")
        needs_review_1 = await _seed_finding(
            factory, assessment_id=a1, cve="CVE-1", outcome=FindingOutcome.NEEDS_REVIEW
        )
        await _seed_finding(
            factory,
            assessment_id=a1,
            cve="CVE-2",
            outcome=FindingOutcome.NOT_AFFECTED,
            tier=EvidenceTier.PROOF,
            justification=Justification.CODE_NOT_PRESENT,
            confidence=Confidence.HIGH,
            decided_by="bob",
            decided_at=datetime.now(UTC),
        )
        needs_review_2 = await _seed_finding(
            factory, assessment_id=a2, cve="CVE-3", outcome=FindingOutcome.NEEDS_REVIEW
        )

        _login(client, "rev")

        all_rows = client.get("/api/review/findings").json()
        assert len(all_rows) == 3

        by_state = client.get("/api/review/findings", params={"state": "needs_review"}).json()
        assert {row["id"] for row in by_state} == {needs_review_1, needs_review_2}

        by_app = client.get("/api/review/findings", params={"application_id": "app-1"}).json()
        assert len(by_app) == 2
        assert all(row["application_id"] == "app-1" for row in by_app)

        by_assessment = client.get("/api/review/findings", params={"assessment_id": a1}).json()
        assert {row["assessment_id"] for row in by_assessment} == {a1}


@pytest.mark.asyncio
async def test_queue_filters_by_sla_band(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="rev", roles=(Role.REVIEWER,))
        overdue_assessment = await _seed_assessment(
            factory, submitted_at=datetime.now(UTC) - timedelta(hours=48)
        )
        fresh_assessment = await _seed_assessment(factory, submitted_at=datetime.now(UTC))
        breaching = await _seed_finding(factory, assessment_id=overdue_assessment, cve="CVE-OLD")
        ok = await _seed_finding(factory, assessment_id=fresh_assessment, cve="CVE-NEW")

        _login(client, "rev")

        breaching_rows = client.get("/api/review/findings", params={"sla": "breaching"}).json()
        assert {row["id"] for row in breaching_rows} == {breaching}

        ok_rows = client.get("/api/review/findings", params={"sla": "ok"}).json()
        assert {row["id"] for row in ok_rows} == {ok}


# --- Evidence drawer / structural separation ------------------------------


@pytest.mark.asyncio
async def test_finding_detail_separates_escalation_signals_from_rule_trace(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="rev", roles=(Role.REVIEWER,))
        assessment_id = await _seed_assessment(factory)
        finding_id = await _seed_finding(
            factory,
            assessment_id=assessment_id,
            rule_results=[
                _TIER1_CLEAR_RULE,
                {
                    "rule_id": "t3-kev",
                    "rule_version": "1",
                    "verdict": State.UNDER_INVESTIGATION,
                    "tier": EvidenceTier.ESCALATION,
                    "detail_json": {
                        "rule_verdict": "satisfied",
                        "cve": "CVE-2024-0001",
                        "kev": True,
                    },
                },
                {
                    "rule_id": "t3-epss",
                    "rule_version": "1",
                    "verdict": State.UNDER_INVESTIGATION,
                    "tier": EvidenceTier.ESCALATION,
                    "detail_json": {
                        "rule_verdict": "satisfied",
                        "cve": "CVE-2024-0001",
                        "epss": 0.9,
                    },
                },
            ],
        )

        _login(client, "rev")
        body = client.get(f"/api/review/findings/{finding_id}").json()

        # Escalation signals are their own top-level object...
        assert body["escalation"]["kev"] is True
        assert body["escalation"]["epss"] == 0.9
        assert body["escalation"]["note"] == "not a basis for clearing"

        # ...and never appear inside the clearing-evidence rule trace.
        trace_rule_ids = {entry["rule_id"] for entry in body["rule_trace"]}
        assert trace_rule_ids == {"t1-class-absent"}
        for entry in body["rule_trace"]:
            assert "kev" not in entry["detail"]
            assert "epss" not in entry["detail"]


# --- Recommend -------------------------------------------------------------


@pytest.mark.asyncio
async def test_recommend_records_an_audit_entry_without_mutating_the_finding(
    tmp_path: Path,
) -> None:
    stub_iq = _StubIq()
    async with _client(tmp_path, iq=stub_iq) as (client, factory):
        await _seed_user(factory, username="rev", roles=(Role.REVIEWER,))
        assessment_id = await _seed_assessment(factory)
        finding_id = await _seed_finding(factory, assessment_id=assessment_id)

        _login(client, "rev")
        response = client.post(
            f"/api/review/findings/{finding_id}/recommend",
            json={"outcome": "not_affected", "justification": "code_not_present"},
        )

        assert response.status_code == 200, response.text
        assert stub_iq.create_calls == []

        async with factory() as db_session:
            finding = await db_session.get(Finding, finding_id)
            assert finding.outcome is FindingOutcome.NEEDS_REVIEW  # unchanged

            entries = (await db_session.execute(select(AuditEntry))).scalars().all()
            assert any(e.action == "finding.recommended" for e in entries)


@pytest.mark.asyncio
async def test_recommend_requires_the_recommend_capability(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="risk", roles=(Role.RISK_MANAGER,))
        assessment_id = await _seed_assessment(factory)
        finding_id = await _seed_finding(factory, assessment_id=assessment_id)

        _login(client, "risk")
        response = client.post(
            f"/api/review/findings/{finding_id}/recommend", json={"outcome": "needs_review"}
        )
        assert response.status_code == 403


# --- Decide: commit ----------------------------------------------------------


@pytest.mark.asyncio
async def test_committing_not_affected_creates_the_iq_suppression(tmp_path: Path) -> None:
    stub_iq = _StubIq()
    async with _client(tmp_path, iq=stub_iq) as (client, factory):
        await _seed_user(factory, username="approver", roles=(Role.APPROVER,))
        assessment_id = await _seed_assessment(factory, requester="alice")
        finding_id = await _seed_finding(
            factory, assessment_id=assessment_id, rule_results=[_TIER1_CLEAR_RULE]
        )

        _login(client, "approver")
        response = client.post(
            f"/api/review/findings/{finding_id}/decide",
            json={"outcome": "not_affected", "justification": "code_not_present"},
        )

        assert response.status_code == 200, response.text
        assert response.json()["outcome"] == "not_affected"
        assert len(stub_iq.create_calls) == 1

        async with factory() as db_session:
            links = (
                (
                    await db_session.execute(
                        select(IqDeterminationLink).where(
                            IqDeterminationLink.finding_id == finding_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(links) == 1

            entries = (await db_session.execute(select(AuditEntry))).scalars().all()
            assert any(e.action == "finding.determined.not_affected" for e in entries)

        assert "waiver" not in response.text.lower()


@pytest.mark.asyncio
async def test_committing_affected_writes_an_audit_entry_and_calls_iq_nothing(
    tmp_path: Path,
) -> None:
    stub_iq = _StubIq()
    async with _client(tmp_path, iq=stub_iq) as (client, factory):
        await _seed_user(factory, username="approver", roles=(Role.APPROVER,))
        assessment_id = await _seed_assessment(factory, requester="alice")
        finding_id = await _seed_finding(factory, assessment_id=assessment_id)

        _login(client, "approver")
        response = client.post(
            f"/api/review/findings/{finding_id}/decide", json={"outcome": "affected"}
        )

        assert response.status_code == 200, response.text
        assert response.json()["outcome"] == "affected"
        assert stub_iq.create_calls == []

        async with factory() as db_session:
            entries = (await db_session.execute(select(AuditEntry))).scalars().all()
            assert any(e.action == "finding.determined.affected" for e in entries)


@pytest.mark.asyncio
async def test_risk_acceptance_required_creates_nothing_in_iq_and_leaves_the_violation_open(
    tmp_path: Path,
) -> None:
    """RISK_ACCEPTANCE_REQUIRED is assigned only by the automated pipeline
    (no fix available — CLAUDE.md rule 5) and is never a value `decide`
    accepts (see `app.schemas.review.DecideRequest`'s own docstring: it is a
    hand-off, never a human's choice to commit). This seeds a finding
    exactly as `app.services.determination.determine` would leave one, and
    checks the review surface reflects the hand-off honestly: no
    suppression exists, and the finding never shows as resolved.
    """
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="rev", roles=(Role.REVIEWER,))
        assessment_id = await _seed_assessment(factory)
        finding_id = await _seed_finding(
            factory,
            assessment_id=assessment_id,
            outcome=FindingOutcome.RISK_ACCEPTANCE_REQUIRED,
            decided_by="system",
            decided_at=datetime.now(UTC),
            rule_results=[
                {
                    "rule_id": "t3-no-fix-available",
                    "rule_version": "1",
                    "verdict": State.UNDER_INVESTIGATION,
                    "tier": EvidenceTier.ESCALATION,
                    "detail_json": {
                        "rule_verdict": "satisfied",
                        "cve": "CVE-2024-0001",
                        "fix_available": False,
                    },
                }
            ],
        )

        _login(client, "rev")
        body = client.get(f"/api/review/findings/{finding_id}").json()

        assert body["outcome"] == "risk_acceptance_required"
        assert body["determination"] is None  # never rendered as a resolved determination
        assert body["escalation"]["fix_available"] is False

        async with factory() as db_session:
            links = (
                (
                    await db_session.execute(
                        select(IqDeterminationLink).where(
                            IqDeterminationLink.finding_id == finding_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert links == []


@pytest.mark.asyncio
async def test_a_tier2_clear_without_a_second_confirmation_is_refused(tmp_path: Path) -> None:
    stub_iq = _StubIq()
    async with _client(tmp_path, iq=stub_iq) as (client, factory):
        await _seed_user(factory, username="approver", roles=(Role.APPROVER,))
        assessment_id = await _seed_assessment(factory, requester="alice")
        # Only Tier 2 (STRONG) evidence on the trace — no Tier 1 proof — so
        # the achieved tier this finding can commit at is STRONG.
        finding_id = await _seed_finding(
            factory,
            assessment_id=assessment_id,
            rule_results=[
                {
                    "rule_id": "t2-not-referenced",
                    "rule_version": "1",
                    "verdict": State.NOT_AFFECTED,
                    "tier": EvidenceTier.STRONG,
                    "detail_json": {"rule_verdict": "satisfied", "cve": "CVE-2024-0001"},
                }
            ],
        )

        _login(client, "approver")

        no_confirmer = client.post(
            f"/api/review/findings/{finding_id}/decide",
            json={
                "outcome": "not_affected",
                "justification": "code_not_reachable",
            },
        )
        assert no_confirmer.status_code == 422
        assert stub_iq.create_calls == []

        self_confirmer = client.post(
            f"/api/review/findings/{finding_id}/decide",
            json={
                "outcome": "not_affected",
                "justification": "code_not_reachable",
                "second_confirmer": "approver",
            },
        )
        assert self_confirmer.status_code == 422
        assert stub_iq.create_calls == []

        with_confirmer = client.post(
            f"/api/review/findings/{finding_id}/decide",
            json={
                "outcome": "not_affected",
                "justification": "code_not_reachable",
                "second_confirmer": "second-approver",
            },
        )
        assert with_confirmer.status_code == 200, with_confirmer.text
        assert len(stub_iq.create_calls) == 1


@pytest.mark.asyncio
async def test_a_requester_cannot_commit_their_own_assessment_even_holding_approver(
    tmp_path: Path,
) -> None:
    """The single most important separation-of-duties test in this suite:
    holding APPROVER does not override it — `app.services.authorization
    .assert_may_commit_own_determination` is keyed on the actor's identity
    against `Assessment.requester`, independent of role.
    """
    stub_iq = _StubIq()
    async with _client(tmp_path, iq=stub_iq) as (client, factory):
        await _seed_user(factory, username="alice", roles=(Role.REQUESTER, Role.APPROVER))
        assessment_id = await _seed_assessment(factory, requester="alice")
        finding_id = await _seed_finding(
            factory, assessment_id=assessment_id, rule_results=[_TIER1_CLEAR_RULE]
        )

        _login(client, "alice")
        response = client.post(
            f"/api/review/findings/{finding_id}/decide",
            json={"outcome": "not_affected", "justification": "code_not_present"},
        )

        assert response.status_code == 403
        assert stub_iq.create_calls == []

        async with factory() as db_session:
            finding = await db_session.get(Finding, finding_id)
            assert finding.outcome is FindingOutcome.NEEDS_REVIEW  # untouched


@pytest.mark.asyncio
async def test_decide_requires_the_commit_capability(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="rev", roles=(Role.REVIEWER,))
        assessment_id = await _seed_assessment(factory, requester="alice")
        finding_id = await _seed_finding(factory, assessment_id=assessment_id)

        _login(client, "rev")
        response = client.post(
            f"/api/review/findings/{finding_id}/decide", json={"outcome": "affected"}
        )
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_deciding_completes_the_assessment_once_every_finding_is_resolved(
    tmp_path: Path,
) -> None:
    async with _client(tmp_path) as (client, factory):
        await _seed_user(factory, username="approver", roles=(Role.APPROVER,))
        assessment_id = await _seed_assessment(factory, requester="alice")
        finding_id = await _seed_finding(factory, assessment_id=assessment_id)

        _login(client, "approver")
        client.post(f"/api/review/findings/{finding_id}/decide", json={"outcome": "affected"})

        async with factory() as db_session:
            assessment = await db_session.get(Assessment, assessment_id)
            assert assessment.state is AssessmentState.COMPLETED
