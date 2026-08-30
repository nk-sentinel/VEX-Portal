# Exploitability Assessment Portal — Design Plan

*(working directory: `nexusiq_Review_portal`)*

## Context

**Problem.** A 4-person AppSec team supports ~2,500 developers on Sonatype Nexus IQ
Lifecycle 203.4. Requests arrive off-process (Teams, email, service requests) and are
reviewed with a hand-run Claude skill. Nothing is tracked, nothing is reused, and review
quality depends on who runs it. This does not scale.

**Why IQ alone can't solve it.** IQ's reachability analysis is not dependable enough to
act on (Java/JS/.NET only, call-path evidence for Java only, nothing for containers,
opt-in at scan time). IQ cannot read source, cannot inspect built artifacts, and has no
view of runtime exposure. Its auto-waiver engine keys on only `threatLevel`, `reachable`,
and `pathForward` — no EPSS, KEV, CWE, config, or artifact-content awareness.

**Intended outcome.** Requests raised in one place; the majority resolved
deterministically with no AI and no human; AI handling a constrained middle band with
evidence-bound reasoning; humans seeing only genuinely ambiguous cases — with a full
audit trail.

**Environment.** Fully airgapped. Claude via AWS Bedrock in a private VPC. Bitbucket Data
Center. JFrog Artifactory. Vulnerability intelligence from Sonatype's feed via IQ's vuln
lookup API — this carries KEV and EPSS, so both are available offline.

**Build location.** Developed in the user's personal environment (shadowlab), then moved
inside the work network for end-to-end integration. Every external system therefore sits
behind an adapter interface with recorded fixtures, and no work data lives in the repo.

---

## Terminology

The portal does not use the word "waiver". Audit and management read it as suppressing a
real issue. The portal records a **determination that a vulnerability does not apply**,
using CycloneDX VEX vocabulary:

| Portal term | Meaning | IQ mechanism (internal only) |
|---|---|---|
| **Exploitability Assessment** | A request to assess whether a CVE applies to an app | — |
| **Not Affected** | Determination: the vulnerability is not exploitable here | IQ waiver, 7 days |
| **Affected** | Determination: it is exploitable | No waiver; remediate |
| **Under Investigation** | Insufficient evidence, awaiting human review | No waiver |
| **Reassessment** | A fresh request after the 7-day window | New assessment |

The IQ waiver is the *enforcement mechanism* of a determination, never the subject. UI,
notifications, and reports use the left column only.

---

## Assessment flow

**Intake is on-demand only. The portal never triggers scans and never auto-renews.**

1. Requester supplies: **IQ report URL** + **JFrog artifact coordinates** (image ref for
   containerised apps) + questionnaire answers
2. **Admission checks** — request rejected up front if any fail:
   - IQ report still exists and is retrievable (14-day purge window is the app team's
     responsibility; requests are reviewed immediately)
   - Artifact exists in JFrog and is retrievable
   - **Artifact belongs to the report** — see Provenance below
3. **Snapshot everything** — raw report JSON, vuln lookups, dependency data, artifact
   inventory stored in the portal. Never a pointer into a system that purges.
4. **Deterministic rules** (Tiers 1–2) run first; most requests resolve here
5. **AI adjudication** for the constrained middle band, evidence-bound, closed enum
6. **Determination** recorded; if *Not Affected*, a 7-day IQ waiver is created
7. **Expiry** — determination lapses at 7 days. No auto-renewal; the app team raises a
   fresh request.

### Why 7 days is correct here
All branches scan into the same IQ app, so a determination made against branch A cannot
be assumed valid for branch B, which may reach a vulnerable method A does not. The short
window is a deliberate risk-limiting device, not a default.

### Optional: early-revocation watch (not auto-renewal)
A daily job re-runs vuln lookup for active determinations. If `isKev` flips true or an
exploit is published inside the 7-day window, it **alerts AppSec** — it does not act
automatically. Grants stay on-demand; only the warning is automated.

---

## Provenance — proving the artifact matches the report

**Primary: dependency-set fingerprint match (needs nothing from CI).** The IQ raw report
lists every component with its hash. The artifact contains bundled jars, also hashable.
If it is the scanned build, the sets match. Divergence beyond threshold → reject at
admission.

**For containerised apps** the artifact is an image, not a binary: pull the image, walk
the layers (`archive/tar` + `compress/gzip`), locate the app binary inside, then run the
same fingerprint match against it.

**Supporting evidence, in descending strength:**
1. JFrog Build Info — `GET /api/build/{name}/{number}` → `vcs:[{url,revision,branch}]`
   plus artifact checksums. Authoritative where published; confirm whether builds publish it
2. Artifact properties — AQL `items.find({"@vcs.revision":{"$eq":"<sha>"}})`. Mutable, weaker
3. Embedded metadata — `BOOT-INF/classes/git.properties`, `META-INF/build-info.properties`.
   Self-verifying and already present in most Spring Boot builds

### Open verification: does IQ hold commit + branch?
The intake design assumes commit/branch can be read from the IQ report. IQ only has them
if the Jenkins plugin sent them (it auto-discovers via `GIT_COMMIT`/`GIT_BRANCH`, or by
walking to `.git`). **Check one existing report before relying on this.** Fallback if
absent: requester supplies the commit, verified against `git.properties` in the artifact
plus the fingerprint match.

---

## Deterministic decision tiers

**Tier 1 — proof. Auto-determination of *Not Affected* is safe.**
1. Vulnerable class absent from the shipped artifact (`rootCauses[].listOfPaths` vs
   artifact contents) — catches shading, minimization, `<filters>`, tree-shaking
2. Component absent from the runtime artifact entirely (inspect artifact, not manifest)
3. Affected submodule not packaged
4. App decommissioned / not deployed → scan-target cleanup, not a determination
5. CVE withdrawn/disputed/superseded → Security Vulnerability Override API, not a determination

**Tier 2 — strong evidence. Auto-determination only with independent second confirmation.**
6. **Constant-pool analysis** — parse the app's own compiled `.class` files; every
   referenced class appears in the constant pool. No reference to the vulnerable class
   means compiled-reality evidence of non-use. Stronger than source grep and catches what
   grep misses
7. Source symbol search via Bitbucket (complements #6; each catches the other's misses)
8. Required companion/gadget component absent from the classpath
9. Required config precondition absent **and** the library default is safe
10. Runtime version immune (JDK/Node/.NET outside the affected range)

**Mandatory anti-check for #6–#7:** `Class.forName`, `ServiceLoader`, `META-INF/services`,
`@ComponentScan`, `newInstance`, SpEL, JNDI, reflection config. Any hit forces manual review.

**Tier 3 — escalation only. Never contributes to a *Not Affected* determination.**
Per user constraint, app context is not reliably available and must not justify a
determination. Tier 3 signals may **only** raise severity or route to manual review:
- CVSS vector attributes, EPSS, KEV
- CWE class vs app type
- Transitive depth
This is enforced one-directionally in the rule engine and property-tested.

**Hard blockers — never an auto-determination:** `kevData.isKev == true` · reachable with
call-path evidence · EPSS above threshold · CVSS ≥ 9 with `AV:N/PR:N/UI:N`.

### Dependency scope handling
| Scope | Ships? | Present at runtime? | Auto-determinable |
|---|---|---|---|
| `test`, npm `devDependencies` | No | No | **Yes** — verify from artifact |
| `provided` | No | **Yes** — container/JDK supplies it | **No** — check the version the runtime supplies |
| `optional` | If declared here | Yes | No |
| `compile` / `runtime` | Yes | Yes | No |

### No fix available
Never a *Not Affected* determination. The portal marks the case
`RISK_ACCEPTANCE_REQUIRED`, produces the evidence package, and the app team takes it to
their risk manager out-of-band. No integration, no automation. **The violation stays OPEN
in IQ** — accepted risk must not be made invisible.

---

## AI adjudication

- **Input:** a fixed evidence pack, never a free-form question
- **Output:** closed enum only —
  `{state, justification, confidence, evidence_refs[], missing_evidence[]}` using VEX
  justification vocabulary
- **Abstention is required:** `insufficient_evidence` → routes to human. Without it the
  "unsure" bucket stays silently empty
- **CVE-intrinsic cache:** what a CVE requires and which classes it implicates is
  app-independent — computed once, cached org-wide, reused. Only applicability is per-app.
  This is what makes a 7-day cycle affordable at 2,500 developers
- **Second refute-pass** on any auto-*Not Affected* path; disagreement → human
- **`similarWaivers` is reviewer context, never a verdict.** Non-exploitable in app A
  implies nothing about app B

---

## RBAC

Authentication mirrors IQ, which uses AD security groups. The portal calls IQ **as the
user** with their user token; `GET /api/v2/applications` returns only the applications
that user may read, so app-level entitlement is inherited rather than reimplemented.

| Role | Capability | Source |
|---|---|---|
| **Requester** (app team) | Raise assessments for apps they can read in IQ | IQ entitlement via user token |
| **Reviewer** (AppSec) | Review queue, evidence, recommend determination | AD group |
| **Approver** (AppSec) | Commit determination; creates the IQ waiver | AD group |
| **Auditor / Management** | Read-only dashboard: volumes, outcomes, SLA, agreement rates | AD group |
| **Risk Manager** | View of `RISK_ACCEPTANCE_REQUIRED` cases and their packages | AD group |
| **Admin** | Rule versions, thresholds, adapter config | AD group |

**Separation of duties:** requester ≠ approver, enforced at the state machine. Reviewer
recommends; approver commits. Every transition is written to an append-only audit log.

---

## Technology

**Python + FastAPI backend · Angular frontend · SQLite**, mirroring DAST-Portal's backend
layout so the same rotation maintains both.

Measured from the existing DAST-Portal estate rather than assumed:

| Layer | Direct deps | Installed packages |
|---|---|---|
| Angular 21.2 frontend | 24 | **377** |
| FastAPI backend | ~63 declared | **46** |

The frontend carries ~8× the backend's dependency surface, so the OSS patch burden that
motivated excluding React is a *frontend* problem. The backend choice is close to
irrelevant to it — Go would have saved ~30 backend packages at the cost of a language the
team does not use. Not a trade worth making.

Angular chosen over a zero-npm server-rendered option because this portal joins an estate
of six-plus internal portals maintained by four people; one consistent frontend pattern is
worth more than the package count. Accepted cost: Angular majors ship roughly every six
months with 18-month LTS, so a major upgrade lands about annually (Angular 21 LTS ends
May 2027). Note the portal will generate IQ violations on its own build-time npm tree —
those go through this portal's own process, which is a useful dogfooding signal.

Python's standard library covers every artifact-inspection need: `zipfile` reads JAR/WAR,
`tarfile` + `gzip` read container image layers, and Java class constant pools parse with
`struct`. No third-party dependency is required for Tier 1 or Tier 2 evidence collection.

Backend layout mirrors DAST-Portal: `app/{adapters,api,domain,repos,schemas,services,
middleware,rules}`, Alembic migrations, SQLAlchemy async + asyncpg, `ldap3` for AD-backed
RBAC, ruff + mypy + pytest with `-W error` discipline, and pinned (never floated) versions.

---

## Data model (core tables)

- `assessment` — app_id, repo, commit_sha, report_id, artifact_ref, state, outcome, requester, expires_at
- `assessment_finding` — assessment_id, cve, purl, policy_id, violation_id_snapshot, threat_level
- `evidence` — assessment_id, collector, key, value_json, source_ref, collected_at
- `cve_profile` — cve, intrinsic_analysis_json, model_version, computed_at *(org-wide cache)*
- `rule_result` — assessment_id, rule_id, rule_version, verdict, confidence
- `ai_verdict` — assessment_id, model_id, prompt_version, state, justification, confidence, refuted_by
- `iq_waiver_link` — assessment_id, policy_waiver_id, expiry, created_at
- `audit_log` — append-only

---

## IQ API surface

| Purpose | Endpoint |
|---|---|
| Entitlement + app list (as user) | `GET /api/v2/applications` |
| Report data | `GET /api/v2/applications/{appId}/reports/{reportId}/raw`, `.../policy` |
| Vuln enrichment (KEV, EPSS, CVSS, rootCauses) | `GET /api/v2/vulnerabilities/{id}?componentIdentifier=` |
| Fix availability, direct-vs-transitive | `POST /api/v2/components/remediation/application/{appId}?stageId=` |
| Reviewer context | `GET /api/v2/policyViolations/{id}/similarWaivers` |
| Existing-waiver check | `GET /api/v2/policyViolations/{id}/applicableWaivers` |
| Create waiver (bulk ≤1000, atomic) | `POST /api/v2/policyWaivers/{ownerType}/{ownerId}[/{violationId}]` |
| Reconciliation | `GET /api/v2/reports/waivers/stale` |
| Structured reasons | `GET /api/v2/waiverReasons` |
| Data correction | Security Vulnerability Override API |
| App → repo (read; create on first use) | `GET/POST /api/v2/sourceControl/application/{appId}` |

Waivers carry `expireWhenRemediationAvailable: true` and a structured `waiverReasonId`;
the IQ comment holds the assessment ID and a one-line reason, with full rationale in the
portal. Cases key on `(appId, CVE, purl)` — violation IDs change on re-scan.

---

## Phased delivery

**Phase 1 — evidence pipeline, offline.** Adapter interfaces + recorded fixtures for IQ,
Bitbucket, JFrog, Bedrock. Assessment model, admission checks, snapshotting, provenance
fingerprint. Fully testable in the personal environment.

**Phase 2 — deterministic rule engine.** Tiers 1–2, versioned and declaratively defined.
Property test: no Tier 3 signal alone ever yields *Not Affected*.

**Phase 3 — AI adjudicator.** Evidence pack, closed enum, CVE-profile cache, refute pass.

**Phase 4 — UI, RBAC, dashboards.** Intake, review queue, evidence viewer, auditor and
risk-manager views.

**Phase 5 — move inside the work network.** Swap fixtures for live adapters, run in
shadow mode against real requests: portal determines, humans determine, agreement
measured per rule.

**Phase 6 — enable auto-determination**, per rule, only for Tier 1 rules clearing the
agreement bar. Then Tier 2 with mandatory second confirmation.

---

## Lifecycle and retirement

- **Determinations** lapse at 7 days; no renewal. The IQ waiver is deleted on early
  revocation, left to lapse otherwise
- **Evidence snapshots** retained for the audit window, independent of IQ's 14-day purge
- **Rules** are versioned; a rule's auto-determination privilege is revoked automatically
  if its agreement rate drops below the bar
- **The hand-run Claude skill** is retired at Phase 6, kept read-only until then as the
  shadow-mode baseline

---

## Verification

- **Collectors** — replay against recorded fixtures; each testable in isolation
- **Provenance** — feed a deliberately mismatched artifact and a container image whose
  inner binary differs; admission must reject both
- **Rule engine** — unit tests per rule; property test that Tier 3 alone never yields
  *Not Affected*; anti-check test that a reflection hit always forces manual review
- **AI adjudicator** — golden-set replay reporting agreement and abstention rates;
  regression gate on every prompt change
- **RBAC** — a requester with no IQ read access to an app cannot raise or view its
  assessment; requester cannot approve their own request
- **End-to-end (Phase 5)** — a known test-scope CVE must auto-determine *Not Affected*
  with a correctly scoped 7-day IQ waiver; a known KEV CVE must never auto-determine
- **Expiry** — determination lapses at 7 days with no renewal path reachable

---

## Open items

- Confirm whether IQ reports already carry commit hash + branch (one report inspection)
- Confirm whether CI publishes JFrog Build Info (determines provenance strength)
- Confirm the container registry path for image-based apps


## Database revision (supersedes the Postgres assumption above)

SQLite, not Postgres. Two things changed the calculus:

1. **ELK already holds SBOM and vulnerability data per scan.** The portal references it
   rather than copying it, and snapshots only the decision-relevant extract. That removes
   the bulkiest thing the database was carrying.
2. **A managed Postgres has real recurring cost in the work environment.** The remaining
   workload — hundreds to low thousands of assessments a year, 10–50 findings each, small
   JSON evidence extracts, an append-only audit log, and a CVE profile cache — stays under a
   few GB indefinitely. It is not a Postgres-shaped workload.

Accepted trade-offs: single writer and single replica, so no horizontal scaling and brief
downtime on rolling deploys; a persistent volume is required; and some enterprise DBA
policies prohibit embedded databases for auditable systems, which would be a hard block.

Mitigation: the schema is kept strictly portable — generic `JSON` rather than `JSONB`
operators, no array columns, no dialect-specific server defaults. Moving to a server
database later is a connection-string change plus a migration, not a rewrite.
