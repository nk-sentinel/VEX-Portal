# Source-based exploitability review — requirements

Reset 2026-10-19. Replaces the artifact-based intake. Implementation order:
`docs/implementation/source-only-review.md`.

## What changes

| | Before | Now |
|---|---|---|
| Inputs | report URL + JFrog artifact coordinates | **report URL only** |
| SCM + SBOM | IQ `source_control` + artifact `git.properties` | **ELK `sbom_data` lookup** |
| Evidence from | compiled bytecode | **source at the scanned commit** |
| Resolution | rules, then AI on Tier 2 | **script first, AI for the rest** |
| Vuln data | IQ vuln lookup | unchanged — **no internet at work**, IQ is the only source |
| AI | Bedrock | unchanged — Bedrock |
| Intake | on demand | on demand **+ cron** |

## Flow

```
report URL ──▶ app_id + report_id ──▶ iq.report() ──▶ scan_id
                                                        │
                                   elk.sbom_for_scan(scan_id)
                                                        │
                                      repo_url + commit + SBOM
                                                        │
                                   bitbucket archive at commit
                                                        ▼
                      ┌──────────── per CVE ────────────────────────┐
                      │                                             │
     iq.vulnerability(cve, purl)                    SCRIPT PASS      │
     iq.remediation(app, purl)            grep the source tree:      │
       → CVSS/EPSS/KEV, rootCauses          · is the package imported?
       → fix available, direct/transitive   · is the implicated type used?
       → affected range                     · is the vulnerable method called?
                      │                     · any reflection / DI escape hatch?
                      │                                             │
                      └──────────────────┬──────────────────────────┘
                                         ▼
                        hard blocker? ───── yes ──▶ HUMAN
                        no fix?       ───── yes ──▶ RISK_ACCEPTANCE_REQUIRED
                        script settled it? ─ yes ──▶ AI confirms (refute pass)
                        script unsure?  ──────────▶ AI decides, then refute pass
                                         │
                                         ▼
                             agree → NOT_AFFECTED / AFFECTED
                             disagree or abstain → HUMAN
```

## R1 — Script pass (the first-line resolver)

Deterministic, offline, over the source tree fetched once at the assessed commit. No
network per CVE.

| Check | Input | Resolves to |
|---|---|---|
| Package imported | `purl` → package/namespace; `is_transitive` from `iq.remediation()` | **Direct** dependency with no first-party import → strong non-use signal. **Transitive** → inconclusive, not a signal |
| Implicated type referenced | `rootCauses[].listOfPaths` → type names | Not referenced anywhere in first-party source → `code_not_reachable` |
| Vulnerable method called | the method name from the root cause, where IQ gives one | Not called → `code_not_reachable`, narrower and stronger than the type check |
| Escape hatches present | reflection, `Class.forName`, `ServiceLoader`, DI annotations, SpEL, JNDI, dynamically built class names | Any hit → **the scan is inconclusive**; nothing above may be read as absence |

**Direct vs transitive is load-bearing.** "No first-party source imports this package" means
nothing for a transitive dependency — the intermediate library is what uses it. A grep rule
that ignores `is_transitive` will clear transitive findings on no evidence at all. It must
branch on it.

**The anti-check carries over unchanged.** An inconclusive scan is never evidence of
absence. This is the same property `t2-not-referenced` enforces today on bytecode, and it
must be enforced the same way on source.

Script evidence is **Tier 2 (STRONG)**, not Tier 1. Source inspection is defeasible —
reflection and dependency injection reach code that no import statement shows. The engine
already demands an independent second confirmation for Tier 2, and that confirmation is the
AI refute pass. This is what "script + AI" means mechanically: the script proposes, the AI
confirms or refutes, and disagreement goes to a human.

Language scope: Java first, matching the existing sample and `rootCauses` format. The module
is structured per-language so a second one is an addition, not a rewrite.

## R2 — AI pass

Handles what the script cannot settle: configuration-dependent CVEs, "only exploitable when
called this way", transitive chains, anything needing reasoning across files.

It is given: the script's findings and *why* they were inconclusive where they were, the
source snippets at the call sites, the implicated types, direct-vs-transitive, the affected
version range, and the repo + commit the evidence came from.

It is **not** given CVSS, EPSS or KEV — unchanged, and deliberate: those are checked earlier
and a hard-blocked finding never reaches the model.

Unchanged from today: closed-enum output through a forced tool call, abstention routes to a
human, and a refute pass runs on every proposed clear.

**The prompt must be rebuilt.** All five evidence fields `_build_prompt` sends today are
artifact-derived (`provenance_verdict`, `class_present`, `referenced`,
`reference_scan_conclusive`, `escape_hatches`). Left as-is, the model receives an empty
package under this flow and correctly abstains on everything — the automation would run and
decide nothing.

## R3 — No internet

The work environment has no outbound internet. Everything about a vulnerability comes from
**IQ's vuln lookup**, which carries KEV and EPSS offline. No NVD, no EPSS API, no OSV, no
GitHub advisory calls — not as a fallback, not for enrichment.

The only outbound destinations are Nexus IQ, ELK, Bitbucket DC and Bedrock. Worth a test
that asserts it, since this is the kind of constraint a well-meaning enrichment patch
violates quietly.

## R4 — Fetching source

One archive fetch per assessment, then everything offline:

```
GET /rest/api/latest/projects/{key}/repos/{slug}/archive?at={commit}&format=zip
```

Ref-exact, one request, and the analysis then mirrors the existing artifact pipeline — fetch
bytes, walk the archive, scan offline. `app/artifact/`'s structure transfers directly, with
source text parsing in place of constant pools.

Why not code search: `search_symbol` cannot scope to a ref (`app/adapters/bitbucket/client.py`
— it accepts one and documents that Bitbucket's search ignores it), the query DSL is
unverified, and the fake implements a plain substring match. An unscoped index search over
the default branch is the wrong evidence for a determination about a specific commit. Keep
`search_symbol` for reviewer context; the archive is what the script pass reads.

The fake needs an archive route. The existing raw-file endpoint already honours `at`, so
per-file reads at a commit work today as a fallback.

## R5 — Admission

Artifact and provenance checks are replaced. Four ordered, fail-fast checks, each with a
message the requester can act on:

| Check | Fails when | Requester sees |
|---|---|---|
| 1. Report | `iq.report()` cannot resolve it | Report purged or the URL is wrong — re-scan and resubmit |
| 2. Scan record | `sbom_data` has no document for this scan | The scan is not indexed yet |
| 3. **Report ↔ index agree** | The IQ report's component set and the ELK record's differ | The two systems describe different builds — nothing downstream is trustworthy |
| 4. Source resolvable | The repo or commit cannot be read at that ref | Commit garbage-collected, repo moved, or the mapping is wrong |

Check 3 is the hard stop, and it is what replaces the artifact fingerprint. Both
`RawReport.components` and `ScanRecord.components` carry `purl` + `sha1` for the same build
from two independently populated systems; comparing them catches a mismatched build. Too
few components to compare is refused exactly like a confirmed mismatch, as
`Verdict.INSUFFICIENT_DATA` is today.

What is genuinely gone: nothing proves the scanned *binary* was built from the assessed
source. Accepted, and stated on the assessment detail screen rather than left implicit.

## R6 — ELK lookup

`ScanRecord` gains `repository_url`, `commit_sha`, `branch` and an indexed timestamp.

Two things to verify at work before this is relied on:

- **`scan_id` is currently `report_id`** (`app/adapters/iq/client.py:299`) — an assumption.
  If they differ, the lookup needs IQ's real scan identifier.
- **The query shape** (`_search` with a `term` on `scan_id.keyword`) is standard
  Elasticsearch, not confirmed against the real mapping.

Also: `RawReport.commit_sha` and `.branch` are always `None` — IQ's report body carries
neither. ELK is the only source for the commit.

ELK is currently the one adapter with no fake and no real-HTTP test coverage
(`httpx.MockTransport` only). It is about to gate admission, so it needs a fifth fake.

## R7 — Scheduled review

Admin-set, stored in the database because it is an audited decision, not an infrastructure
fact.

| Field | Notes |
|---|---|
| `cron_expression` | 5-field cron, validated on save. Needs `croniter`, pinned |
| `scope_mode` | `all_applications` \| `selected` |
| `patterns_json` | Globs matched against the IQ application id — `app1_test`, `app2*`. JSON list, not an array column |
| `enabled` | Off by default |
| `max_per_run` | Cap per tick. A bare `*` on first run would otherwise start hundreds of reviews at once |
| `last_run_at` / `next_run_at` / `watermark` | Persisted, so a restart neither double-fires nor skips |
| `updated_by` / `updated_at` | Audit trail |

Matching is `fnmatch` on the application id, case-sensitive (IQ ids are). The admin screen
shows which application ids currently match **before** the schedule is saved.

A tick: find due schedules → `elk.scans_since(watermark)` → filter by glob → skip any
(app, report) that already has an unexpired assessment → raise up to `max_per_run` → advance
the watermark. One tick at a time; a still-running tick skips the next window and records
that it did. In-process on the FastAPI lifespan — SQLite has one writer and the deployment
is single-replica.

Two small decisions, settled rather than left open:

- **Requester:** auto-raised assessments get a synthetic `system:scheduler` requester and a
  new `Assessment.origin` column (`manual` | `scheduled`), shown in the queue. Separation of
  duties does not constrain who approves them — there is no human requester to exclude —
  and `origin` is what makes that visible instead of implicit.
- **`docs/design.md` says "Intake is on-demand only."** That sentence gets rewritten. Cron
  starts *reviews*; it does not renew determinations, and the 7-day expiry rule is untouched.

## R8 — Roles and where a finding lands

**Reviewer and approver are one seat.** The reviewer role now holds
`COMMIT_DETERMINATION` as well as `RECOMMEND_DETERMINATION`. Separation of duties is
untouched — it compares the actor against `Assessment.requester`, which is the app team, so
merging the two AppSec seats removes no control. Already implemented.

The three-way routing the requirement describes is the outcome model that already exists;
no new states are needed, only the source-based evidence feeding it:

| Case | Outcome | What the requester sees | Nexus IQ |
|---|---|---|---|
| **False positive** — script and AI agree it is not exploitable | `NOT_AFFECTED` | Not Affected, with the justification and evidence | Determination recorded, 7 days |
| **True positive** — exploitable | `AFFECTED` | Affected. Nothing cleared, because it is real | Violation stays open |
| **Looks like a false positive but needs a human** | `NEEDS_REVIEW` | In review, with what was collected | Nothing written until a reviewer decides |
| **No fix exists** | `RISK_ACCEPTANCE_REQUIRED` | Hand-off to the risk manager | Violation stays open |

What routes a finding into the third row, rather than the first: a hard blocker, any rule
answering `UNANSWERABLE`, the adjudicator abstaining (`INSUFFICIENT`/`LOW` confidence), or
the refute pass disagreeing with the primary verdict. Every one of those is an explicit
"not confident enough to clear this", which is the only reason a human should be spending
time on it.

Nothing is written to Nexus IQ for an `AFFECTED` or `NEEDS_REVIEW` finding. A true positive
is visibly *not* cleared in the portal, which is the point — the requester gets told their
finding is real, not that it is pending.

## R9 — AI configuration

Bedrock, as today. No second provider. What becomes configurable rather than hardcoded:

| Setting | Today |
|---|---|
| `ai_model_id` | `bedrock_model_id`, already config |
| `ai_max_tokens` | hardcoded 1024 |
| `ai_timeout_seconds` | hardcoded 30.0 |
| `ai_enabled` | implicit — no way to run script-only |

`ai_enabled=false` runs the script pass alone and routes everything it cannot settle to a
human. Useful for a first rollout, and for measuring how much the script actually resolves
before the model is in the loop.

## Open, needs the real environment

- Does IQ's vuln lookup return call-path reachability? `Tier3Signals.reachable_with_call_path`
  has no source anywhere; until confirmed it reads `None`, which does not block.
- The real `sbom_data` mapping: field names, whether SCM is present per scan, the scan
  identifier, the timestamp field.
- Whether IQ's `rootCauses` gives a method name or only a class path — the method-level
  check in R1 depends on it.
- Bitbucket DC's archive endpoint path on the installed version.
