# VEX Portal — working notes

Full design: `docs/design.md`. Naming and vocabulary rationale: `docs/naming.md`.
Read both before changing behaviour.

## Non-negotiable rules

**1. Never use the word "waiver" in anything user-facing.** UI copy, API field names,
notifications, reports, docs. Audit and management read it as suppressing a real finding.
The portal records *determinations*; the IQ waiver is an implementation detail confined to
`app/adapters/iq/`. See the terminology table in README.md.

**2. Tier 3 evidence may never clear a finding.** CVSS vector, EPSS, KEV, exposure and app
criticality may raise severity or route to a human — never justify Not Affected. App context
is not reliably available in this environment. Enforced in
`app/domain/determination.py::Determination.validate` and property-tested in
`tests/domain/test_determination.py`. If a test there fails, the portal has become capable of
clearing something it should not.

**3. The adjudicator must be able to abstain.** `Confidence.INSUFFICIENT` routes to human
review regardless of proposed state. Without an abstain path the "unsure" bucket stays
silently empty and ambiguous cases get forced into confident-looking verdicts.

**4. Determinations expire at 7 days and are never auto-renewed.** All branches scan into the
same IQ application, so a determination against branch A cannot be assumed valid for branch B.

**5. No fix available is not a Not Affected determination.** It is `RISK_ACCEPTANCE_REQUIRED`,
handled by the app team with their risk manager, out of band. The IQ violation stays open.

## Conventions

- Mirrors DAST-Portal layout: `app/{adapters,api,domain,repos,schemas,services,middleware,rules}`
- Dependency versions are **pinned, never floated** — this portal reviews OSS vulnerability
  findings; an unpinned tree here would be an unforced risk as well as an unforced irony
- **The database is SQLite, and the schema must stay portable.** No `JSONB` operators (use
  generic `JSON`), no array columns, no dialect-specific server defaults (`gen_random_uuid()`,
  `NOW()`) — generate IDs and timestamps in Python. Enable `PRAGMA foreign_keys=ON` and WAL
  mode. A managed server DB has real monthly cost in the work environment and this workload
  does not need one; keeping the schema portable means that decision stays reversible
- Single replica only — SQLite cannot be shared across app instances. Rolling deploys take
  brief downtime; that is an accepted trade
- Do not add a `Co-Authored-By` trailer to commits

## External systems

| System | Role |
|---|---|
| Nexus IQ | System of record for the waiver (enforcement). Report data, vuln lookup (carries KEV + EPSS offline), remediation, app→repo mapping |
| Bitbucket DC | Source for symbol search |
| JFrog Artifactory | Built artifacts and container images — Tier 1 evidence and provenance |
| ELK | SBOM + vulnerability data per scan. **Reference it, don't copy it** — but snapshot the decision-relevant extract, because an audit trail that depends on another team's retention policy is not a trail |
| Bedrock | Claude adjudicator, private VPC |

## Current state

Phase 1 (evidence pipeline). Domain vocabulary and its safety invariants are done and
tested (46 tests).

- UI spec: `docs/design/ui-spec.md` — 9 screens + evidence drawer. Angular not started.
- **Next up:** `docs/plans/2026-08-31-evidence-foundation.md` — 8 TDD tasks building the
  offline evidence engine (artifact inspection, constant-pool analysis, container layer
  walking, provenance fingerprint). No third-party dependencies, no external systems, so
  it is entirely buildable outside the work network.
- Plans 2 (adapters + persistence) and 3 (rule engine + services + API) are outlined at
  the end of that document.
