"""Tests for `app/api/assessments.py` — POST/GET /api/assessments,
GET /api/assessments/{id}, GET /api/applications.

The happy-path test rounds-trips against the three live fakes (IQ, JFrog,
Bitbucket — and, for the ambiguous/KEV findings, the fact that Bedrock is
never even called is asserted directly) using the documented `payments-api`
sample scenario (`fakes/README.md`), mirroring how `tests/services/
test_admission.py` and `tests/services/test_collection.py` already validate
each stage of the same pipeline. Every other case uses stub adapters so the
failure/authorization paths are deterministic and do not depend on the fakes
running at all.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.errors import UpstreamResponseError
from app.adapters.protocols import (
    Application,
    ArtifactStore,
    IqClient,
    RawReport,
    ReportComponent,
)
from app.api.deps import get_artifact_store_dep, get_iq_client_dep
from app.db import get_session, make_engine, session_factory
from app.main import create_app
from app.repos.models import AuditEntry, Base, IqDeterminationLink, Role, User
from tests.adapters.support import (
    BITBUCKET_BASE_URL,
    IQ_BASE_URL,
    JFROG_BASE_URL,
    require_reachable,
)
from tests.artifact.factories import make_class_file, make_jar, make_spring_boot_jar

_PASSWORD = "correct horse battery staple"  # noqa: S105 - test fixture, not a real credential

# The live fakes' one documented sample scenario (fakes/README.md) — the
# same ids `tests/services/test_admission.py` and `tests/services/
# test_collection.py` use.
APP_ID = "4f6d8a2c9b1e4a7f8c3d2b1a0f9e8d7c"
REPORT_ID = "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
COORDINATES = "libs-release-local/com/example/payments-api/1.0.0/payments-api-1.0.0.jar"


class _StubIq:
    """A minimal, Protocol-conforming `IqClient` for admission/entitlement
    failure paths — only `applications_for_user`/`report` are ever reached
    before those paths refuse the request."""

    def __init__(
        self,
        *,
        applications: list[Application] | None = None,
        report: RawReport | None = None,
        report_error: Exception | None = None,
        applications_error: Exception | None = None,
    ) -> None:
        default_applications = [Application(id=APP_ID, name="Payments API")]
        self._applications = applications if applications is not None else default_applications
        self._report = report
        self._report_error = report_error
        self._applications_error = applications_error

    async def applications_for_user(self, user_token: str) -> list[Application]:
        if self._applications_error is not None:
            raise self._applications_error
        return self._applications

    async def report(self, application_id: str, report_id: str) -> RawReport:
        if self._report_error is not None:
            raise self._report_error
        assert self._report is not None
        return self._report

    async def vulnerability(self, vuln_id: str, component_purl: str | None):  # pragma: no cover
        raise NotImplementedError

    async def remediation(self, application_id: str, purl: str):  # pragma: no cover
        raise NotImplementedError

    async def source_control(self, application_id: str):
        # collect_evidence always calls this, even for a report with no
        # violations — None is a legitimate "no mapping" answer, never an
        # error, per app.adapters.protocols.IqClient's own signature.
        return None

    async def create_determination(self, finding, options):  # pragma: no cover
        raise NotImplementedError

    async def revoke_determination(self, link_id: str) -> None:  # pragma: no cover
        raise NotImplementedError


class _StubArtifactStore:
    def __init__(self, *, data: bytes | None = None, error: Exception | None = None) -> None:
        self._data = data
        self._error = error

    async def fetch(self, coordinates: str) -> bytes:
        if self._error is not None:
            raise self._error
        assert self._data is not None
        return self._data

    async def build_info(self, coordinates: str):  # pragma: no cover - unused
        raise NotImplementedError


def _artifact_and_report(*, matching: bool) -> tuple[bytes, RawReport]:
    """A minimal, real archive plus a report whose component hashes either
    match it (provenance MATCH) or don't (provenance mismatch) — mirrors
    `tests/services/test_admission.py`'s own helper."""
    libraries = {f"lib-{i}.jar": make_jar({f"pkg/C{i}.class": bytes([i])}) for i in range(6)}
    artifact = make_spring_boot_jar(
        app_classes={"com/example/App.class": make_class_file(["java/lang/String"])},
        libraries=libraries,
    )
    if matching:
        hashes = {hashlib.sha1(payload).hexdigest() for payload in libraries.values()}
    else:
        hashes = {hashlib.sha1(f"unrelated-{i}".encode()).hexdigest() for i in range(6)}
    components = [
        ReportComponent(purl=f"pkg:generic/lib-{i}", sha1=h) for i, h in enumerate(hashes)
    ]
    report = RawReport(
        components=components, violations=[], scan_id="scan-1", commit_sha=None, branch=None
    )
    return artifact, report


async def _seed_user(
    factory: async_sessionmaker[AsyncSession],
    *,
    username: str = "alice",
    password: str = _PASSWORD,
    roles: Iterable[Role] = (Role.REQUESTER,),
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


@asynccontextmanager
async def _client(
    tmp_path: Path,
    *,
    iq: IqClient,
    artifact_store: ArtifactStore | None = None,
) -> AsyncIterator[tuple[TestClient, async_sessionmaker[AsyncSession]]]:
    """A `TestClient` with `get_session` pointed at a scratch database and
    the IQ/artifact-store adapters overridden to stubs — mirrors
    `tests/api/conftest.py`'s `db_client`, extended with the adapter
    dependencies this route module needs (`app/api/deps.py`'s
    `get_iq_client_dep`/`get_artifact_store_dep`).
    """
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/assessments-test.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)

    async def _override_get_session() -> AsyncIterator[AsyncSession]:
        async with factory() as db_session:
            yield db_session

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session
    app.dependency_overrides[get_iq_client_dep] = lambda: iq
    if artifact_store is not None:
        app.dependency_overrides[get_artifact_store_dep] = lambda: artifact_store

    with TestClient(app) as client:
        yield client, factory

    await engine.dispose()


def _login(client: TestClient, username: str = "alice") -> None:
    response = client.post("/api/auth/login", json={"username": username, "password": _PASSWORD})
    assert response.status_code == 200, response.text


_RAISE_BODY = {
    "application_id": APP_ID,
    "report_id": REPORT_ID,
    "artifact_coordinates": COORDINATES,
    "requester_note": "need this for the Q3 release",
}


# --- Live-fakes happy path ---------------------------------------------------


@pytest.mark.asyncio
async def test_raising_runs_admission_and_reaches_a_determination(tmp_path: Path) -> None:
    for base_url in (IQ_BASE_URL, JFROG_BASE_URL, BITBUCKET_BASE_URL):
        require_reachable(base_url)

    from app.adapters.bitbucket.client import BitbucketHttpClient
    from app.adapters.iq.client import IqHttpClient
    from app.adapters.jfrog.client import JFrogHttpClient

    iq = IqHttpClient(base_url=IQ_BASE_URL, service_user="svc", service_token="tok")  # noqa: S106
    jfrog = JFrogHttpClient(base_url=JFROG_BASE_URL, token="tok")  # noqa: S106
    bitbucket = BitbucketHttpClient(base_url=BITBUCKET_BASE_URL, token="tok")  # noqa: S106

    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/live.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)

    async def _override_get_session() -> AsyncIterator[AsyncSession]:
        async with factory() as db_session:
            yield db_session

    from app.api.deps import get_artifact_store_dep, get_iq_client_dep, get_source_repository_dep

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session
    app.dependency_overrides[get_iq_client_dep] = lambda: iq
    app.dependency_overrides[get_artifact_store_dep] = lambda: jfrog
    app.dependency_overrides[get_source_repository_dep] = lambda: bitbucket

    try:
        with TestClient(app) as client:
            await _seed_user(factory)
            _login(client)

            response = client.post("/api/assessments", json=_RAISE_BODY)
            assert response.status_code == 201, response.text
            body = response.json()

            assert body["state"] == "needs_review"  # 2 of 3 findings need review
            findings_by_cve = {f["cve"]: f for f in body["findings"]}
            assert set(findings_by_cve) == {"CVE-2022-42889", "CVE-2021-44228", "CVE-2015-6420"}

            # KEV-blocked: never clears, regardless of Tier 1/2 evidence.
            assert findings_by_cve["CVE-2022-42889"]["outcome"] == "needs_review"
            # Ambiguous reference scan / high EPSS: also routes to review.
            assert findings_by_cve["CVE-2021-44228"]["outcome"] == "needs_review"
            # Tier 1 proof of absence: clears deterministically, no AI needed.
            cleared = findings_by_cve["CVE-2015-6420"]
            assert cleared["outcome"] == "not_affected"
            assert cleared["tier"] == "PROOF" or cleared["tier"] == 1 or cleared["tier"] == "proof"
            assert cleared["justification"] == "code_not_present"
            assert cleared["evidence_refs"]

            # The clear must have produced a real IQ suppression.
            async with factory() as db_session:
                links = (await db_session.execute(select(IqDeterminationLink))).scalars().all()
                assert len(links) == 1

            # "waiver" must never appear anywhere in the response.
            assert "waiver" not in response.text.lower()
    finally:
        await engine.dispose()


# --- Admission failures -------------------------------------------------------


@pytest.mark.asyncio
async def test_provenance_mismatch_is_refused_with_a_message_naming_the_mismatch(
    tmp_path: Path,
) -> None:
    artifact, mismatched_report = _artifact_and_report(matching=False)
    async with _client(
        tmp_path,
        iq=_StubIq(report=mismatched_report),
        artifact_store=_StubArtifactStore(data=artifact),
    ) as (client, factory):
        await _seed_user(factory)
        _login(client)

        response = client.post("/api/assessments", json=_RAISE_BODY)

        assert response.status_code == 422
        detail = response.json()["detail"]
        assert detail["check"] == "provenance"
        assert "does not match report" in detail["message"]
        assert "waiver" not in response.text.lower()


@pytest.mark.asyncio
async def test_report_unavailable_is_refused_as_a_report_check_failure(tmp_path: Path) -> None:
    async with _client(
        tmp_path,
        iq=_StubIq(report_error=UpstreamResponseError("GET", "/reports/x", 404)),
        artifact_store=_StubArtifactStore(data=b"unused"),
    ) as (client, factory):
        await _seed_user(factory)
        _login(client)

        response = client.post("/api/assessments", json=_RAISE_BODY)

        assert response.status_code == 422
        assert response.json()["detail"]["check"] == "report"


@pytest.mark.asyncio
async def test_admission_failure_is_persisted_and_visible_on_my_assessments(tmp_path: Path) -> None:
    artifact, mismatched_report = _artifact_and_report(matching=False)
    async with _client(
        tmp_path,
        iq=_StubIq(report=mismatched_report),
        artifact_store=_StubArtifactStore(data=artifact),
    ) as (client, factory):
        await _seed_user(factory)
        _login(client)
        client.post("/api/assessments", json=_RAISE_BODY)

        listing = client.get("/api/assessments")
        assert listing.status_code == 200
        rows = listing.json()
        assert len(rows) == 1
        assert rows[0]["state"] == "admission_failed"
        assert rows[0]["admission_failure"]["check"] == "provenance"

        async with factory() as db_session:
            entries = (await db_session.execute(select(AuditEntry))).scalars().all()
            assert any(e.action == "assessment.admission_failed" for e in entries)


# --- Entitlement -------------------------------------------------------------


@pytest.mark.asyncio
async def test_requesting_an_application_not_in_the_callers_iq_entitlement_is_refused(
    tmp_path: Path,
) -> None:
    async with _client(
        tmp_path,
        iq=_StubIq(applications=[Application(id="some-other-app", name="Other")]),
    ) as (client, factory):
        await _seed_user(factory)
        _login(client)

        response = client.post("/api/assessments", json=_RAISE_BODY)

        assert response.status_code == 403
        assert "waiver" not in response.text.lower()


@pytest.mark.asyncio
async def test_applications_endpoint_lists_only_what_iq_returns(tmp_path: Path) -> None:
    async with _client(
        tmp_path,
        iq=_StubIq(
            applications=[Application(id="app-1", name="One"), Application(id="app-2", name="Two")]
        ),
    ) as (client, factory):
        await _seed_user(factory)
        _login(client)

        response = client.get("/api/applications")

        assert response.status_code == 200
        assert {a["id"] for a in response.json()} == {"app-1", "app-2"}


# --- Ownership / RBAC ---------------------------------------------------------


@pytest.mark.asyncio
async def test_a_requester_sees_only_their_own_assessments(tmp_path: Path) -> None:
    artifact, mismatched_report = _artifact_and_report(matching=False)
    async with _client(
        tmp_path,
        iq=_StubIq(report=mismatched_report),
        artifact_store=_StubArtifactStore(data=artifact),
    ) as (client, factory):
        await _seed_user(factory, username="alice")
        await _seed_user(factory, username="bob")

        _login(client, "alice")
        client.post("/api/assessments", json=_RAISE_BODY)
        client.post("/api/auth/logout")

        _login(client, "bob")
        client.post("/api/assessments", json=_RAISE_BODY)

        response = client.get("/api/assessments")
        assert response.status_code == 200
        rows = response.json()
        assert len(rows) == 1
        assert rows[0]["requester"] == "bob"


@pytest.mark.asyncio
async def test_raise_assessment_requires_the_requester_capability(tmp_path: Path) -> None:
    async with _client(tmp_path, iq=_StubIq()) as (client, factory):
        await _seed_user(factory, username="rev", roles=(Role.REVIEWER,))
        _login(client, "rev")

        assert client.post("/api/assessments", json=_RAISE_BODY).status_code == 403
        assert client.get("/api/assessments").status_code == 403
        assert client.get("/api/applications").status_code == 403


@pytest.mark.asyncio
async def test_raise_assessment_without_a_session_is_401(tmp_path: Path) -> None:
    async with _client(tmp_path, iq=_StubIq()) as (client, factory):
        assert client.post("/api/assessments", json=_RAISE_BODY).status_code == 401


@pytest.mark.asyncio
async def test_assessment_detail_is_visible_to_owner_reviewer_and_nobody_else(
    tmp_path: Path,
) -> None:
    artifact, matching_report = _artifact_and_report(matching=True)
    async with _client(
        tmp_path,
        iq=_StubIq(report=matching_report),
        artifact_store=_StubArtifactStore(data=artifact),
    ) as (client, factory):
        await _seed_user(factory, username="alice", roles=(Role.REQUESTER,))
        await _seed_user(factory, username="rev", roles=(Role.REVIEWER,))
        await _seed_user(factory, username="carol", roles=(Role.REQUESTER,))

        _login(client, "alice")
        created = client.post("/api/assessments", json=_RAISE_BODY).json()
        assessment_id = created["id"]
        client.post("/api/auth/logout")

        _login(client, "alice")
        assert client.get(f"/api/assessments/{assessment_id}").status_code == 200
        client.post("/api/auth/logout")

        _login(client, "rev")
        assert client.get(f"/api/assessments/{assessment_id}").status_code == 200
        client.post("/api/auth/logout")

        _login(client, "carol")
        assert client.get(f"/api/assessments/{assessment_id}").status_code == 403


@pytest.mark.asyncio
async def test_assessment_not_found_is_404(tmp_path: Path) -> None:
    async with _client(tmp_path, iq=_StubIq()) as (client, factory):
        await _seed_user(factory)
        _login(client)

        assert client.get("/api/assessments/does-not-exist").status_code == 404
