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

**All six phases complete. The portal runs end to end at `vex.shadow-lab.org`.**
608 backend tests, 348 Karma specs, 95 live API round-trips. ruff + mypy strict clean.

Evidence engine → decision engine → API + access → nine screens. Four fake vendor servers
stand in for Nexus IQ, JFrog, Bitbucket and Bedrock; one setting swaps them for the real
systems at work.

### Decide before the work deployment

1. **No per-user Nexus IQ token exists.** App entitlement is meant to be inherited by calling
   IQ with the *user's* token, precisely so the portal never keeps a parallel permission model
   that drifts. Neither auth provider issues one; the session username is a placeholder. The
   intended mechanism is IQ's User Token feature — decide where the token lives (session-only
   vs encrypted at rest) and how it is captured.
2. **Collector failures are not persisted.** `EvidencePack.failures` is built but never stored
   or exposed, so the UI cannot actually distinguish a failed collector from an abstention —
   a distinction the design depends on, since one is an outage and the other a limit of the
   evidence.
3. **`/docs` is publicly reachable** through the Cloudflare tunnel. Endpoints require auth but
   the full API surface is readable.
4. **Bulk approval has no eligible target** — the pipeline auto-commits everything safe before
   a finding reaches the queue, so every queued row needs individual attention. Either drop
   bulk from the design or add a "proposed but uncommitted" state.
5. **`java/lang/Class` is too broad an escape-hatch marker** — `Object.getClass()` is
   ubiquitous, so Tier 2 will rarely fire on real bytecode. Narrowing it is the *unsafe*
   direction, so it needs a human decision. Fix is resolving `CONSTANT_Methodref` so the
   marker requires `Class.forName` specifically.

### Verify at work, cannot be confirmed here

Bitbucket DC's code-search response shape; server-side search scoping (the client filters
client-side today); IQ's `waiverReasonId` catalogue (matched by text); the LDAP bind-DN shape;
the six AD group DNs; `SESSION_COOKIE_SECURE=true`; and that escape-hatch markers fire on real
`javac` output — there is no JDK here.

### Known gaps, documented not hidden

Three rules are written, tested and deliberately UNREGISTERED because their evidence source
does not exist (`t1-cve-withdrawn`, `t2-gadget-absent`, `t2-runtime-immune`) — see
`app/rules/registry.py::PENDING_EVIDENCE`. No SSO endpoint despite the mockups showing one.
No branch field on assessments. No time-series dashboard data. Migrations are not wired for
the containerised instance.

Full decision log — 60+ rulings with rationale and cost-if-wrong — lives in
`.superpowers/sdd/*/progress.md` (git-ignored, local only).
