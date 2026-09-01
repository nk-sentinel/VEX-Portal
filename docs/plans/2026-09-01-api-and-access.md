# API and Access Management — Phase 5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Make the decision engine reachable. Login, roles, and the endpoints the nine screens will call.

**Architecture:** An auth provider chosen by config — local users in the database for shadowlab and break-glass, LDAP/AD at work — behind one interface so nothing downstream knows which is in use. Roles map to capabilities; separation of duties is enforced at the state machine, not in the UI.

**Spec:** `docs/design/ui-spec.md` (the screens these endpoints serve, and the RBAC table), `docs/design.md`.

## Global Constraints

- Python `>=3.12`. One new dependency: `argon2-cffi` (already in `pyproject.toml`'s dev list — promote it to runtime). Nothing else.
- **Never the word "waiver"** in a route, request field, response field, or error message. This is the layer users and screens actually see.
- **Authorisation is server-side.** A role check that exists only in the UI is decoration. Every endpoint enforces its own capability.
- **Separation of duties: a requester may never approve their own assessment.** Enforced in the service layer, tested directly.
- **App-level entitlement is inherited from Nexus IQ, not reimplemented.** `GET /api/v2/applications` called with the user's own token returns exactly the applications they may read. Do not build a parallel permission model that will drift from IQ's.
- Passwords are argon2. Never logged, never returned, never in an error.
- `ruff check app tests` and `mypy app` (strict) must pass. Line length 100.
- The existing 471 tests must keep passing.

---

### Task 1: Auth providers and the user model

**Files:** `app/repos/models.py` (add `User`, `Role`), `app/auth/providers.py`, `app/auth/local.py`, `app/auth/ldap.py`, migration; tests.

**Produces:** `AuthProvider` Protocol (`authenticate(username, password) -> AuthenticatedUser | None`), `LocalAuthProvider`, `LdapAuthProvider`, `Role` enum, `get_auth_provider(settings)`.

`Role`: `REQUESTER`, `REVIEWER`, `APPROVER`, `AUDITOR`, `RISK_MANAGER`, `ADMIN`.

- [ ] Tests: a correct password authenticates; a wrong one returns `None` **and takes comparable time** (argon2 gives this, but assert the failure path does a hash rather than returning early — an early return on unknown username leaks which usernames exist); the password hash never appears in `repr`, logs, or any API response; roles round-trip; the LDAP provider maps groups to roles from config; an unmapped group yields no role rather than a default one.

**Why the timing test:** an early return for an unknown user makes account enumeration trivial. This portal's user list is the AppSec team and the app teams they serve — worth not leaking.

---

### Task 2: Sessions and login

**Files:** `app/api/auth.py`, `app/middleware/session.py`; tests.

Signed cookie sessions via `itsdangerous`, `session_secret` from config. `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`.

- [ ] Tests: login sets a session; `me` returns identity and roles; logout clears it; a tampered cookie is rejected; the session secret never appears in a response; an expired session is rejected.

**`GET /api/auth/me` must return the roles the server believes**, not what the client claims — the screens use it to decide what to render, and that is a convenience, never the enforcement point.

---

### Task 3: RBAC dependency and separation of duties

**Files:** `app/api/deps.py`, `app/services/authorization.py`; tests.

A FastAPI dependency `requires(Capability)`. Capabilities rather than roles at the call site, so a role change is one mapping edit.

| Capability | Roles |
|---|---|
| `raise_assessment` | Requester |
| `view_queue` | Reviewer, Approver, Auditor |
| `recommend_determination` | Reviewer, Approver |
| `commit_determination` | Approver |
| `view_dashboard` | Auditor, Admin |
| `view_risk_acceptance` | Risk Manager, Auditor |
| `manage_rules` | Admin |

- [ ] Tests: each capability admits exactly its roles and rejects the rest; an unauthenticated request is 401 not 403; **a requester cannot commit a determination on their own assessment even holding APPROVER** — that is the separation-of-duties test and it must exercise the service, not the route.

---

### Task 4: Assessment endpoints

**Files:** `app/api/assessments.py`, `app/schemas/assessments.py`; tests.

- `POST /api/assessments` — raise one. Runs admission; a failure returns 422 with which check failed and what to do.
- `GET /api/assessments` — the caller's own.
- `GET /api/assessments/{id}` — with findings and outcomes.
- `GET /api/applications` — from IQ, scoped to the caller's token.

- [ ] Tests: raising runs admission; a provenance mismatch is refused with a message naming the mismatch; a requester sees only their own; requesting an application they cannot read in IQ is refused; the response contains no "waiver".

---

### Task 5: Review endpoints

**Files:** `app/api/review.py`; tests.

- `GET /api/review/findings` — the queue, filterable by state, application, SLA.
- `GET /api/review/findings/{id}` — the evidence drawer's payload: rule trace, escalation signals, AI verdict, missing evidence.
- `POST /api/review/findings/{id}/recommend`
- `POST /api/review/findings/{id}/decide` — commits; requires `commit_determination`.

**The finding detail response must separate escalation signals from clearing evidence structurally**, not just by label. The UI spec requires they never render as supporting a clear; if the API hands them back in one flat bag, the UI has to remember, and eventually it will not.

- [ ] Tests: the queue filters; a decision writes an audit entry; committing `NOT_AFFECTED` creates the IQ suppression; committing `RISK_ACCEPTANCE_REQUIRED` creates nothing in IQ and leaves the violation open; a Tier 2 clear without a second confirmation is refused.

---

### Task 6: Dashboard, risk acceptance, admin

**Files:** `app/api/dashboard.py`, `app/api/risk.py`, `app/api/admin.py`; tests.

- `GET /api/dashboard/*` — volumes, outcomes, SLA, automation split, per-rule agreement.
- `GET /api/risk-acceptance` + evidence package download.
- `GET/PUT /api/admin/rules` — per-rule auto-determination toggles and thresholds. **A Tier 3 rule has no toggle** — absent, not disabled: rendering a greyed-out control implies the capability exists.
- A threshold change writes an audit entry and returns how many of the last 30 days' findings would have routed differently.

- [ ] Tests: dashboard numbers match the underlying rows; risk-acceptance shows only that outcome; a Tier 3 rule cannot be given a toggle through the API even by crafting the request; every admin change is audited.

---

## Verification

- Log in locally, raise an assessment against the fake IQ, watch it reach a determination, see it in the queue, approve it, confirm the suppression in the fake IQ
- A requester cannot approve their own assessment
- `grep -rin waiver backend/app/api backend/app/schemas` returns nothing
- The 471 existing tests still pass
