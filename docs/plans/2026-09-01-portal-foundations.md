# Portal Foundations — Phases 1 & 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the evidence engine into a running service with a database, and stand up fake versions of the four external systems so the real client code can be exercised on shadowlab.

**Architecture:** FastAPI + SQLAlchemy (async) over SQLite, mirroring DAST-Portal's layout. Every external system sits behind a Protocol with two implementations — a real HTTP client and a fake-server-backed one — selected by config. The fakes are small FastAPI apps serving realistic canned data; they are throwaway scaffolding, never shipped to the work environment.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2 async, aiosqlite, Alembic, pydantic-settings, httpx, Docker Compose behind Traefik.

**Spec:** `docs/design.md` (architecture, evidence tiers, four outcomes), `docs/naming.md` (vocabulary), `docs/design/ui-spec.md` (screens the API must serve).

## Global Constraints

- Python `>=3.12`. Dependency versions **pinned, never floated**.
- **Never the word "waiver"** in any identifier, docstring, log message, error string, API field, or column name. Vocabulary is *determination*, *assessment*, *Not Affected*. The IQ waiver is confined to `app/adapters/iq/`.
- **The schema must stay portable.** Generic `JSON`, never `JSONB` operators. No array columns. No dialect-specific server defaults — generate IDs and timestamps in Python. A server database must remain a connection-string change.
- **SQLite pragmas are not optional:** `foreign_keys=ON` and `journal_mode=WAL` on every connection.
- **Secrets never reach the database or an API response.** Endpoint URLs, credentials and model IDs come from `.env` only. Behaviour tunables (thresholds, per-rule toggles) live in the database and are audited.
- Every external system is reached through a Protocol. No module outside `app/adapters/` may import `httpx` or know a URL.
- `cd backend && .venv/bin/ruff check app tests && .venv/bin/mypy app` must pass (strict). Line length 100.
- `pyproject.toml` sets `filterwarnings = error::DeprecationWarning`.
- The existing 242 tests must keep passing. They are the evidence engine and nothing here may disturb them.

---

## File Structure

| File | Responsibility |
|---|---|
| `backend/app/config.py` | Settings from `.env`; the fake/real adapter switch |
| `backend/app/main.py` | FastAPI app factory, lifespan, health route |
| `backend/app/db.py` | Engine, session factory, SQLite pragmas |
| `backend/app/repos/models.py` | SQLAlchemy ORM models — the eight tables |
| `backend/app/repos/assessments.py` | Assessment + finding persistence |
| `backend/app/repos/audit.py` | Append-only audit log writes |
| `backend/alembic/` | Migration environment and versions |
| `backend/app/adapters/protocols.py` | The five Protocols every adapter satisfies |
| `backend/app/adapters/iq/client.py` | Real Nexus IQ client |
| `backend/app/adapters/jfrog/client.py` | Real JFrog client |
| `backend/app/adapters/bitbucket/client.py` | Real Bitbucket client |
| `backend/app/adapters/llm/bedrock.py` | Real Bedrock client |
| `backend/app/adapters/elk/client.py` | Real ELK client |
| `fakes/iq/main.py` … | Four fake servers (throwaway, not shipped) |
| `fakes/data/` | Canned responses shared by fakes and tests |

---

### Task 1: Settings and the adapter switch

**Files:**
- Create: `backend/app/config.py`
- Modify: `backend/pyproject.toml` (add runtime deps)
- Modify: `.env.example`
- Test: `backend/tests/test_config.py`

**Interfaces:**
- Produces: `Settings` (pydantic-settings), `get_settings() -> Settings` (cached), `AdapterMode` enum (`REAL` / `FAKE`)

- [ ] **Step 1: Write the failing test**

```python
import pytest
from app.config import AdapterMode, Settings


def test_defaults_to_fake_adapters_so_a_misconfigured_deploy_cannot_reach_production():
    # Defaulting to REAL would mean a missing env var silently points a dev
    # instance at the live Nexus IQ. Fake is the safe default.
    assert Settings(_env_file=None).adapter_mode is AdapterMode.FAKE


def test_database_url_defaults_to_a_local_sqlite_file():
    assert Settings(_env_file=None).database_url.startswith("sqlite+aiosqlite://")


def test_secrets_are_not_repeated_in_the_string_form():
    # Settings gets logged during startup diagnostics. A token in __repr__
    # would land in logs and in any error report built from them.
    s = Settings(_env_file=None, iq_service_token="super-secret-token")
    assert "super-secret-token" not in repr(s)
    assert "super-secret-token" not in str(s)


def test_real_mode_requires_every_endpoint():
    # Half-configured REAL mode is worse than FAKE: some calls succeed against
    # production while others fail confusingly.
    with pytest.raises(ValueError, match="iq_base_url"):
        Settings(_env_file=None, adapter_mode="real")
```

- [ ] **Step 2: Run to verify it fails**

`cd backend && PYTHONPATH=. .venv/bin/pytest tests/test_config.py -v` → `ModuleNotFoundError`

- [ ] **Step 3: Add runtime dependencies**

In `backend/pyproject.toml`, the `dependencies` list already names fastapi, uvicorn, sqlalchemy, aiosqlite, alembic, pydantic, pydantic-settings, httpx, ldap3, boto3, python-multipart, itsdangerous. Install them:

```bash
cd backend && .venv/bin/pip install -e '.[dev]'
```

- [ ] **Step 4: Write `app/config.py`**

```python
"""Runtime settings.

Two rules shape this module.

Secrets and infrastructure facts come from the environment, never from the
database or an API response: a token stored in the database appears in backups,
on an admin's screen, and in anything built from a settings dump. Behaviour
tunables — thresholds, per-rule toggles — live in the database instead, because
they are decisions the team makes and must be audited.

The adapter mode defaults to FAKE. Defaulting to REAL would mean one missing
environment variable silently points a development instance at the live Nexus IQ
and creates determinations against real applications.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AdapterMode(StrEnum):
    """Which implementation backs every external system."""

    REAL = "real"
    FAKE = "fake"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", frozen=True
    )

    adapter_mode: AdapterMode = AdapterMode.FAKE

    database_url: str = "sqlite+aiosqlite:///./data/vex.db"

    iq_base_url: str = ""
    iq_service_user: str = ""
    iq_service_token: SecretStr = SecretStr("")

    jfrog_base_url: str = ""
    jfrog_token: SecretStr = SecretStr("")

    bitbucket_base_url: str = ""
    bitbucket_token: SecretStr = SecretStr("")

    elk_base_url: str = ""
    elk_index: str = "sbom-scans-*"
    elk_token: SecretStr = SecretStr("")

    aws_region: str = "us-east-1"
    bedrock_model_id: str = "claude-opus-5"
    bedrock_endpoint_url: str = ""

    ldap_url: str = ""
    ldap_base_dn: str = ""
    ldap_group_reviewer: str = ""
    ldap_group_approver: str = ""
    ldap_group_auditor: str = ""
    ldap_group_risk_manager: str = ""

    #: Where the fake servers listen when adapter_mode is FAKE.
    fake_iq_url: str = "http://localhost:9101"
    fake_jfrog_url: str = "http://localhost:9102"
    fake_bitbucket_url: str = "http://localhost:9103"
    fake_bedrock_url: str = "http://localhost:9104"

    session_secret: SecretStr = SecretStr("dev-only-change-me")

    @model_validator(mode="after")
    def _real_mode_needs_endpoints(self) -> Settings:
        if self.adapter_mode is not AdapterMode.REAL:
            return self
        missing = [
            name
            for name in ("iq_base_url", "jfrog_base_url", "bitbucket_base_url")
            if not getattr(self, name)
        ]
        if missing:
            raise ValueError(
                f"adapter_mode=real requires {', '.join(missing)} — a half-configured "
                "real deployment reaches production for some calls and fails for others"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

`SecretStr` is what keeps tokens out of `repr()` and `str()`.

- [ ] **Step 5: Run tests, lint, types, commit**

```bash
cd backend && PYTHONPATH=. .venv/bin/pytest tests/test_config.py -v
cd backend && .venv/bin/ruff check app tests && .venv/bin/mypy app
git add backend/app/config.py backend/tests/test_config.py backend/pyproject.toml .env.example
git commit -m "Add runtime settings with a fail-safe adapter default

Adapter mode defaults to FAKE: defaulting to REAL would let one missing
environment variable point a development instance at the live Nexus IQ and
create determinations against real applications. Tokens are SecretStr so they
stay out of repr() and any log line built from a settings dump."
```

---

### Task 2: Database engine and SQLite pragmas

**Files:**
- Create: `backend/app/db.py`
- Test: `backend/tests/test_db.py`

**Interfaces:**
- Consumes: `get_settings` (Task 1)
- Produces: `make_engine(url: str) -> AsyncEngine`, `session_factory(engine)`, `get_session()` dependency

- [ ] **Step 1: Write the failing test**

```python
import pytest
from sqlalchemy import text

from app.db import make_engine


@pytest.mark.asyncio
async def test_foreign_keys_are_enforced(tmp_path):
    # SQLite ignores foreign keys unless asked, per connection. Without this a
    # finding can outlive the assessment it belongs to and the audit trail
    # develops holes nothing detects.
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/t.db")
    async with engine.connect() as conn:
        assert (await conn.execute(text("PRAGMA foreign_keys"))).scalar() == 1
    await engine.dispose()


@pytest.mark.asyncio
async def test_write_ahead_logging_is_enabled(tmp_path):
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path}/t.db")
    async with engine.connect() as conn:
        assert (await conn.execute(text("PRAGMA journal_mode"))).scalar().lower() == "wal"
    await engine.dispose()
```

- [ ] **Step 2: Verify it fails**, then write `app/db.py`:

```python
"""Database engine.

SQLite needs two things asked for explicitly on every connection. Foreign keys
are off by default, so without the pragma a finding can outlive the assessment
it belongs to and the audit trail grows holes nothing detects. WAL lets readers
work while a write is in flight, which is what makes a single-file database
usable for a queue several people are watching.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.config import get_settings


def make_engine(url: str) -> AsyncEngine:
    engine = create_async_engine(url, echo=False, future=True)

    @event.listens_for(engine.sync_engine, "connect")
    def _apply_pragmas(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    return engine


_engine: AsyncEngine | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = make_engine(get_settings().database_url)
    return _engine


async def get_session() -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(get_engine(), expire_on_commit=False)
    async with factory() as session:
        yield session
```

- [ ] **Step 3: Tests pass, lint, types, commit**

---

### Task 3: The schema

**Files:**
- Create: `backend/app/repos/models.py`
- Test: `backend/tests/repos/test_models.py`

**Interfaces:**
- Produces: `Base`, and models `Assessment`, `Finding`, `Evidence`, `CveProfile`, `RuleResult`, `AiVerdict`, `IqDeterminationLink`, `AuditEntry`; enums `AssessmentState`, `FindingOutcome`

Eight tables. The shapes matter more than the column list, so the constraints are called out per table.

- [ ] **Step 1: Write the failing tests**

```python
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

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
```

- [ ] **Step 2: Verify failure, then write `app/repos/models.py`**

Requirements, exactly:

- `Base = declarative_base()` with a naming convention for constraints so Alembic autogenerate produces stable names.
- **IDs are `str` UUID4 generated in Python** via `default=lambda: str(uuid4())`. No `gen_random_uuid()`, no autoincrement integers.
- **Timestamps are `datetime` with `tzinfo=UTC`, generated in Python** via `default=lambda: datetime.now(UTC)`. No `func.now()`.
- **JSON columns use `sqlalchemy.JSON`**, never `JSONB`. No array columns anywhere; a list becomes a JSON column or a child table.
- Enums are stored as **strings**, not native database enums, so the schema ports.

Tables:

| Table | Key columns | Notes |
|---|---|---|
| `assessment` | `id`, `application_id`, `report_id`, `scan_id`, `commit_sha`, `repository_url`, `artifact_ref`, `state`, `requester`, `justification`, `created_at`, `submitted_at`, `expires_at` | `state` is `AssessmentState`; `expires_at` set when a determination is committed |
| `finding` | `id`, `assessment_id` FK cascade, `cve`, `purl`, `policy_id`, `violation_id_snapshot`, `threat_level`, `outcome`, `justification`, `tier`, `confidence`, `decided_by`, `decided_at` | unique on `(assessment_id, cve, purl)` — the case's identity, not the violation id |
| `evidence` | `id`, `assessment_id` FK cascade, `finding_id` FK nullable, `collector`, `key`, `value_json` (JSON), `source_ref`, `collected_at` | `source_ref` points at ELK or an artifact digest; the extract itself is stored |
| `cve_profile` | `cve` PK, `intrinsic_json` (JSON), `model_version`, `computed_at` | org-wide cache; app-independent by construction |
| `rule_result` | `id`, `finding_id` FK cascade, `rule_id`, `rule_version`, `verdict`, `tier`, `detail_json` (JSON) | one row per rule that ran |
| `ai_verdict` | `id`, `finding_id` FK cascade, `model_id`, `prompt_version`, `state`, `justification`, `confidence`, `evidence_refs_json`, `missing_evidence_json`, `refuted_by`, `created_at` | `refuted_by` records the second-pass check |
| `iq_determination_link` | `id`, `finding_id` FK cascade, `policy_waiver_id`, `expiry`, `created_at`, `revoked_at` | the ONLY place the IQ waiver id appears |
| `audit_entry` | `id`, `actor`, `action`, `subject_type`, `subject_id`, `detail_json`, `created_at` | append-only, enforced below |

**Append-only enforcement** — a SQLAlchemy event, not a convention:

```python
@event.listens_for(Session, "before_flush")
def _block_audit_mutation(session: Session, _ctx: object, _instances: object) -> None:
    """An audit row that can be edited is not an audit trail.

    Enforced in the ORM rather than by reviewer discipline, because the whole
    value of the log is that nobody can quietly change what it says happened.
    """
    for obj in session.dirty:
        if isinstance(obj, AuditEntry) and session.is_modified(obj):
            raise PermissionError("audit_entry rows are append-only and cannot be modified")
    for obj in session.deleted:
        if isinstance(obj, AuditEntry):
            raise PermissionError("audit_entry rows are append-only and cannot be deleted")
```

`AssessmentState`: `DRAFT`, `ADMISSION`, `ADMISSION_FAILED`, `ANALYSING`, `NEEDS_REVIEW`, `AWAITING_APPROVAL`, `COMPLETED`, `EXPIRED`.
`FindingOutcome`: `NOT_AFFECTED`, `AFFECTED`, `NEEDS_REVIEW`, `RISK_ACCEPTANCE_REQUIRED`.

Both live here and must match `app/domain/determination.py`'s vocabulary — a `Finding` marked `NOT_AFFECTED` must carry a `justification` valid for its `tier`, which the domain module already validates.

- [ ] **Step 3: Tests pass, lint, types, commit**

---

### Task 4: Alembic and the first migration

**Files:**
- Create: `backend/alembic.ini`, `backend/alembic/env.py`, `backend/alembic/script.py.mako`
- Create: `backend/alembic/versions/0001_initial.py`
- Test: `backend/tests/test_migrations.py`

- [ ] **Step 1: Failing test**

```python
@pytest.mark.asyncio
async def test_migration_creates_every_table_the_models_declare(tmp_path):
    # Guards the usual drift: a model added without a migration works in tests
    # (metadata.create_all) and fails on a real deployment.
    ...run alembic upgrade head against a temp database, then compare
    inspect(engine).get_table_names() with Base.metadata.tables...


@pytest.mark.asyncio
async def test_downgrade_then_upgrade_is_clean(tmp_path):
    ...
```

- [ ] **Step 2:** `alembic init`, point `env.py` at `Base.metadata` and `settings.database_url`, set `render_as_batch=True` (SQLite cannot ALTER most things without table rebuild), autogenerate `0001_initial`, review the generated file by hand for dialect-specific types, commit.

---

### Task 5: The app, health, and Docker

**Files:**
- Create: `backend/app/main.py`
- Create: `compose.yaml`
- Modify: `justfile`
- Test: `backend/tests/api/test_health.py`

- [ ] **Step 1: Failing test**

```python
def test_health_reports_adapter_mode_so_nobody_mistakes_fake_for_real(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["adapter_mode"] in {"fake", "real"}


def test_health_never_leaks_a_secret(client):
    assert "token" not in client.get("/health").text.lower()
```

- [ ] **Step 2:** `create_app()` factory, lifespan that disposes the engine, `/health` returning status, adapter mode and version. Compose service `vex-portal-api` on the `proxy` network with Traefik labels for `vex.shadow-lab.org`, entrypoint `web`, no TLS resolver (Cloudflare terminates). Service name is stack-unique per house convention. `just up`, `just dev-api`, `just migrate` targets.

**The health route naming the adapter mode is deliberate** — a fake-backed instance and a real one must be distinguishable at a glance, or someone will demo against fakes believing they are looking at production data.

---

### Task 6: Adapter protocols

**Files:**
- Create: `backend/app/adapters/protocols.py`
- Test: `backend/tests/adapters/test_protocols.py`

Five `typing.Protocol` classes defining exactly what the portal needs. Written from the portal's needs, not from each vendor's API surface, so a vendor change is contained in one client.

```python
class IqClient(Protocol):
    async def applications_for_user(self, user_token: str) -> list[Application]: ...
    async def report(self, application_id: str, report_id: str) -> RawReport: ...
    async def vulnerability(self, vuln_id: str, component_purl: str | None) -> VulnDetail: ...
    async def remediation(self, application_id: str, purl: str) -> Remediation | None: ...
    async def source_control(self, application_id: str) -> SourceControl | None: ...
    async def create_determination(self, finding: FindingRef, options: DeterminationOptions) -> str: ...
    async def revoke_determination(self, link_id: str) -> None: ...

class ArtifactStore(Protocol):
    async def fetch(self, coordinates: str) -> bytes: ...
    async def build_info(self, coordinates: str) -> BuildInfo | None: ...

class SourceRepository(Protocol):
    async def search_symbol(self, repo: str, symbol: str, ref: str) -> list[SymbolHit]: ...
    async def file(self, repo: str, path: str, ref: str) -> bytes | None: ...

class Adjudicator(Protocol):
    async def adjudicate(self, pack: EvidencePack, finding: FindingRef) -> AiVerdictDto: ...

class ScanArchive(Protocol):
    async def sbom_for_scan(self, scan_id: str) -> ScanRecord | None: ...
```

`create_determination` returns the IQ waiver id, and that word appears nowhere outside `app/adapters/iq/`.

- [ ] Test: a fake and a real implementation of each Protocol both satisfy it, checked with `isinstance` against `runtime_checkable` protocols so drift between the two is caught at test time rather than at work.

---

### Task 7: The four fake servers

**Files:**
- Create: `fakes/iq/main.py`, `fakes/jfrog/main.py`, `fakes/bitbucket/main.py`, `fakes/bedrock/main.py`
- Create: `fakes/data/*.json`, `fakes/README.md`
- Modify: `compose.yaml`

**These are throwaway scaffolding.** They exist so the real client code is exercised on shadowlab. They must not grow features, must not be imported by `app/`, and never ship to the work environment. Say so in `fakes/README.md`.

Each is a small FastAPI app serving canned data shaped like the real API:

- **fake IQ** — `GET /api/v2/applications`, `GET /api/v2/applications/{id}/reports/{rid}/raw` and `/policy`, `GET /api/v2/vulnerabilities/{id}` (including `kevData`, `epssData`, `mainSeverity`, `rootCauses`), `POST /api/v2/components/remediation/...`, `GET/POST /api/v2/sourceControl/application/{id}`, `POST /api/v2/policyWaivers/...`, `GET /api/v2/waiverReasons`.
- **fake JFrog** — artifact download returning a real generated Spring Boot fat JAR built with the existing test factories, plus `GET /api/build/{name}/{number}`.
- **fake Bitbucket** — file fetch and a code-search endpoint over a small canned tree.
- **fake Bedrock** — an `InvokeModel`-shaped endpoint returning a fixed, valid adjudication in the exact response envelope, so the parsing and the strict-output contract are exercised here.

Sample data must include at least: one application, one report with a mix of findings (one clearly not-affected, one clearly affected, one ambiguous), one CVE with KEV true, one with a high EPSS, one with no fix available.

- [ ] Test: each fake starts, answers its documented routes, and the corresponding real client parses its responses without special-casing.

---

### Task 8: Real clients against the fakes

**Files:**
- Create: `backend/app/adapters/{iq,jfrog,bitbucket,llm,elk}/client.py`
- Create: `backend/app/adapters/factory.py`
- Test: `backend/tests/adapters/test_*_client.py`

One `httpx.AsyncClient` per adapter, constructed from settings, with timeouts and a bounded retry. `factory.py` returns the real client for both modes — the only difference is the base URL, pointed at the fake server when `adapter_mode` is FAKE.

**That is the point of this design:** there is one client implementation, exercised here against a fake endpoint and at work against the real one. A separate "fake client" class would let the two drift and the real path would be untested until the work environment.

- [ ] Test per client: happy path parses; a 404 becomes a typed absence not an exception; a 500 raises a typed error; a timeout raises a typed error; no secret appears in any log record emitted during a failure.

---

## Self-review

**Spec coverage.** Config, database, schema, migrations, app, Docker, protocols, fakes, clients — everything phases 1 and 2 promised. The eight tables match `docs/design.md`'s data model, with `iq_waiver_link` renamed `iq_determination_link` to honour the vocabulary rule.

**Placeholder scan.** Tasks 3, 4, 7 and 8 specify requirements and table shapes rather than pasting every line; each names exact columns, constraints and test obligations. Tasks 1, 2, 5 carry complete code. Task 4's test bodies are described rather than written because they depend on the Alembic layout generated in the same task.

**Type consistency.** `Settings`/`get_settings` (T1) → `make_engine` (T2) → models (T3) → migrations (T4) → app (T5) → protocols (T6) → fakes (T7) → clients (T8). `AdapterMode` is defined once in T1 and consumed in T5 and T8.

---

## Verification

- `just up && just migrate && just dev-api`, then `GET /health` returns `adapter_mode: fake`
- All four fakes reachable; each real client round-trips against its fake
- `alembic downgrade base && alembic upgrade head` leaves the schema identical
- The 242 evidence-engine tests still pass untouched
- `grep -rin waiver backend/app --include='*.py' | grep -v adapters/iq` returns nothing
- Portal reachable at `vex.shadow-lab.org` through Traefik

---

## Subsequent phases

**Phase 3–4** — admission checks, the tiered rule engine, the AI adjudicator with its refute pass and abstain path, and the four outcomes. The full decision flow, no screens.

**Phase 5** — API endpoints and AD-backed RBAC with separation of duties.

**Phase 6** — the nine Angular screens from `docs/design/ui-spec.md`.
