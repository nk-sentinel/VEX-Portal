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

**Branch `feat/evidence-foundation` — evidence engine + portal foundations. 344 backend tests
+ 31 fakes tests, ruff + mypy clean. Service live at `vex.shadow-lab.org`.**

Two plans are complete: the evidence engine (`docs/plans/2026-08-31-evidence-foundation.md`)
and the portal foundations (`docs/plans/2026-09-01-portal-foundations.md`) — settings with a
fail-safe fake/real switch, SQLite with enforced pragmas, the eight-table schema, Alembic,
the FastAPI app behind Traefik, adapter Protocols, four fake vendor servers, and the real
HTTP clients exercised against them.

**Carry into Phase 3 (decision logic):**
- `IqClient.create_determination` cannot resolve a current `policyViolationId` from
  `FindingRef` alone — it needs report/violation context the Protocol does not carry. Resolved
  today with an extra call; fix the Protocol before the determination-commit service is built.
- IQ's waiver-creation returns `204 No Content`, so the suppression id comes from a follow-up
  `applicableWaivers` read, not from the create call.
- IQ's `rootCauses[].listOfPaths` can contain a bare jar filename — filter to `.class`.
- Migrations are not wired for the containerised instance; the first DB-backed route in the
  container needs an entrypoint decision.

**Verify at work, cannot be confirmed here:** Bitbucket DC's code-search response shape;
server-side search scoping (the client filters client-side today); IQ's `waiverReasonId`
catalogue (matched by text today).

The offline evidence engine: artifact inventory, Java constant-pool parsing, Tier 1 class
presence, Tier 2 reference scanning with dynamic-dispatch anti-checks, container image layer
walking, provenance fingerprinting, the evidence pack, a CLI, security hardening, and
performance benchmarks. Standard library only.

Went through a whole-branch review plus three adversarial fix/re-review rounds. Five Criticals
were found and fixed, four of them by attacking the seam a previous fix created.

### Fixed since the review

**`git.properties` ordering (N4) — resolved.** Canonical ties now resolve by documented
precedence (`BOOT-INF/classes/` > `WEB-INF/classes/` > root), never by ZIP order, so the
determinism the code comment claims is now true. Where two canonical files disagree about the
commit, the higher-precedence value is returned AND `Inventory.git_properties_ambiguous` is
set and surfaced in the evidence pack — an artifact claiming two different commits is a fact a
reviewer should see, not something to resolve silently. The comparison is made on the
*resolved* commit (walking the `git.commit.id.full` -> `git.commit.id` -> `.abbrev` fallback
chain), not one raw key, so a disagreement expressed only through a fallback key still flags.
Raising on a tie was rejected: `commit_sha()` is attacker-authored metadata that no
determination rests on, so refusing an artifact over it would cost availability for nothing.

**Duplicate entry names (N3) — resolved.** An archive is rejected when a duplicated raw entry
name would be READ as evidence: library-prefix entries, and nested archives the presence walk
recurses into. Duplicates that are never read — `META-INF/LICENSE`, `META-INF/services/*`,
routine in shaded JARs — are tolerated, because rejecting them buys no security and a control
that fires on honest builds gets switched off. Note the finding's narrative was slightly wrong:
reads via a captured `ZipInfo` happen to address the correct occurrence, but that is a CPython
implementation detail rather than a guarantee. The genuinely exploitable case was the by-name
read in nested-archive recursion outside a library directory (an EAR module), where duplication
did make `contains_class` return False. Guarded at every read site regardless.

### Decide before merge

1. **Declared metadata is untrusted — apply the rule everywhere.** `file_size` and
   `compress_size` are attacker-controlled. Fixed at the guards that gate evidence; still
   trusted by `enforce_limits`' budget arithmetic and the two `git.properties` reads. Consider
   a central-vs-local-header consistency check.
2. **Surplus tolerance (5%)** means a 100-component build tolerates five entirely unscanned
   bundled JARs and still returns MATCH.
3. **`java/lang/Class` marker breadth.** `Object.getClass()` is ubiquitous, so
   `is_conclusive()` will be False on most real bytecode and Tier 2 will rarely fire. NOT
   changed unattended: narrowing markers makes `is_conclusive()` True more often, the unsafe
   direction. Fix is ~30 lines resolving `CONSTANT_Methodref` so the marker requires
   `Class.forName` specifically.

### Watch

- **Cross-prefix key collisions now raise `MalformedArtifact`** — fail-closed and correct, but
  a new way a legitimate artifact gets refused. Monitor on real builds.
- **`excluded_class_count` is a coverage counter, not a completeness proof.** It counts only
  classes reaching the key function; anything dropped earlier is invisible. Read
  `excluded_classes == 0` as "no *known* gap", never "no gap".
- **Escape-hatch markers were only ever exercised against synthetic class files.** No JDK here,
  so nobody has confirmed they fire on real `javac` output.

Full decision log — 47 rulings with rationale and cost-if-wrong:
`.superpowers/sdd/2026-08-31-evidence-foundation/progress.md` (git-ignored, local only).

- UI spec: `docs/design/ui-spec.md`; mockups `docs/design/ui-mockups.html`. Angular not started.
- Plans 2 (adapters + persistence) and 3 (rule engine + services + API) outlined at the end of
  the plan document.
