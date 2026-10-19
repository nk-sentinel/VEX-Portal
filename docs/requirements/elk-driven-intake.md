# ELK-driven, source-only review — requirements

Stated 2026-10-19. Supersedes the first version of this file, which set out three options
for the artifact-vs-source question. **Option 2 was chosen: source-only.** This version
records the decisions and specifies what they require. Implementation order:
`docs/implementation/source-only-review.md`.

## Decisions taken

| # | Decision | Consequence |
|---|---|---|
| D1 | **Pause the JFrog artifact flow.** Evidence comes from source, not the built binary | Tier 1 proof is unreachable; no finding auto-clears deterministically |
| D2 | **AI adjudication is accepted as the normal path**, not the exception | Every proposed clear goes through the adjudicator plus its refute pass |
| D3 | **The AI provider is configurable** — Claude Enterprise intended at work | New `ai_*` settings block; a second `Adjudicator` implementation beside Bedrock |
| D4 | **Scheduled review is configurable**: a cron expression, plus "all applications" or a glob-matched selection (`app1_test`, `app2*`) | New config table, an in-process scheduler, and an answer to "who is the requester" |

D1 is the load-bearing one. It does not merely move where inputs come from — it changes
what the portal is allowed to decide on its own. D2 is what makes that workable.

## The flow

```
  ┌─ MANUAL ──────────────────┐        ┌─ SCHEDULED (D4) ───────────────┐
  │ user logs in              │        │ cron fires                     │
  │ pastes IQ report URL      │        │ query sbom_data since watermark│
  └───────────┬───────────────┘        │ filter app ids by glob         │
              │                        └───────────┬────────────────────┘
              ▼                                    │
      parse URL SERVER-SIDE                        │
      → (application_id, report_id)                │
              │                                    │
              └──────────────┬─────────────────────┘
                             ▼
        ╔══ ADMISSION ═══════════════════════════════════╗
        ║ 1. report retrievable        iq.report()       ║
        ║ 2. scan record found         elk.sbom_for()    ║
        ║ 3. report ↔ index agree      component sets    ║  ← the hard stop,
        ║ 4. source resolvable         repo + commit     ║    kept in a new form
        ╚════════════════════════┬═══════════════════════╝
                                 ▼
        ╔══ COLLECT ═════════════════════════════════════╗
        ║ per CVE:  iq.vulnerability()  CVSS/EPSS/KEV    ║
        ║           iq.remediation()    fix availability ║
        ║ per repo: bitbucket at commit — symbol search  ║
        ║           + file reads for the implicated types║
        ╚════════════════════════┬═══════════════════════╝
                                 ▼
        ╔══ DECIDE ══════════════════════════════════════╗
        ║ Tier 3 rules only → block / escalate, never    ║
        ║                     clear                      ║
        ║ no hard blocker   → ADJUDICATOR + refute pass  ║
        ╚════════════════════════┬═══════════════════════╝
                                 ▼
            NOT_AFFECTED · AFFECTED · NEEDS_REVIEW · RISK_ACCEPTANCE_REQUIRED
                                 │
                       IQ determination, 7-day expiry
```

## Step-by-step requirements

### R1 — Server-side report URL parsing

The URL is parsed in the browser today (`web/.../assessments.model.ts::extractReportId`,
last path segment only) and the backend receives `report_id` alone. The application id in
the same URL is discarded, which is why intake currently has a separate typed field.

Required: the backend accepts the report URL and derives both ids from it. The typed
application id field then goes away again, and the scheduler — which has no browser — gets
the same parsing path as the form.

`https://iq.example.com/assets/index.html#/applicationReport/{application_id}/{report_id}`

A URL that does not match is a request error naming what was expected, never a silent
fallback to treating the whole string as a report id.

### R2 — Resolving source coordinates from `sbom_data`

```
report URL ─▶ application_id + report_id ─▶ iq.report() ─▶ scan_id
                                                             │
                                          elk.sbom_for_scan(scan_id)
                                                             │
                                        repository_url + commit_sha + branch
```

Two things to know about this chain:

- **`scan_id` is currently `report_id`.** `app/adapters/iq/client.py:299` sets
  `scan_id=report_id` — an assumption, not a confirmed IQ fact. If they differ at work, the
  ELK lookup needs IQ's real scan identifier, which must then be found in the report body.
  **Verify first.** If they are the same, no new index key is needed.
- **`RawReport.commit_sha` and `.branch` are always `None`** — IQ's report body carries
  neither (that adapter's own docstring says so). The commit can therefore only come from
  ELK or from the requester. ELK is now the primary source; a requester-supplied commit
  stays as an override.

`ScanRecord` must gain `repository_url`, `commit_sha`, `branch` and an indexed timestamp
(the scheduler's watermark, R6). The current query shape — `_search` with a
`term` on `scan_id.keyword` — is a standard Elasticsearch shape, not a confirmed one.
**Verify against the real index mapping before relying on it.**

### R3 — Admission without an artifact

Admission keeps four ordered, fail-fast checks, each with a message the requester can act
on. Two are new; the provenance hard stop is preserved in a different form.

| Check | What it does | Failure means |
|---|---|---|
| 1. Report | `iq.report()` resolves | The report purged, or the ids are wrong — re-scan and resubmit |
| 2. Scan record | `sbom_data` has a document for this scan | The scan has not been indexed yet, or the index is keyed differently |
| 3. **Report ↔ index agreement** | The IQ report's component set and the ELK record's component set describe the same build | One of the two systems is describing a different build; nothing downstream can be trusted |
| 4. Source resolvable | The repo exists in Bitbucket and the commit is readable at that ref | The commit was garbage-collected, the repo moved, or the mapping is wrong |

**Why check 3 matters.** Dropping the artifact looks like it removes provenance entirely.
It does not have to. Both `RawReport.components` and `ScanRecord.components` carry
`purl` + `sha1` for the same build, from two independently populated systems. Comparing
them is the same class of integrity check the artifact fingerprint performed — "the thing
I am about to reason about is the thing that was scanned" — and it is the only check
standing between a determination and a silently mismatched build. It must be a hard stop,
and "too few components to compare" must be refused the same way a confirmed mismatch is,
exactly as `Verdict.INSUFFICIENT_DATA` is refused today.

What is genuinely lost: the commit proves which *source* was built; nothing now proves the
scanned *binary* was built from it. That gap is accepted under D1 and must be stated on
the assessment detail screen rather than left implicit.

### R4 — Evidence and the rule registry under source-only

The artifact rules cannot be left registered. `t1-class-absent`, `t1-component-absent` and
`t2-not-referenced` all read artifact-derived fields, and all three return `UNANSWERABLE`
when those fields are absent. One `UNANSWERABLE` rule forces *the whole finding* to human
review (`app/rules/engine.py`, priority order point 2) — so leaving them registered with
no artifact routes **every finding** to a human and the automation does nothing at all.

They must be unregistered under source-only, by the same mechanism and for the same stated
reason as `PENDING_EVIDENCE` already uses: the rule classes and their tests stay, the
evidence source is gone, so the rule does not run.

| | Artifact flow (built) | Source-only (D1) |
|---|---|---|
| Tier 1 rules | `t1-class-absent`, `t1-component-absent` | none registered |
| Tier 2 rules | `t2-not-referenced` | none registered |
| Tier 3 rules | `t3-kev`, `t3-epss`, `t3-cvss-vector`, `t3-no-fix` | unchanged |
| Can clear without AI | yes, on Tier 1 proof | **no** |
| Can clear without a human | yes | yes — adjudicator + refute pass |

**Source evidence is not promoted to a registered Tier 2 rule.** It is fed to the
adjudicator instead. Two reasons:

1. Bitbucket DC code search is **not scoped to a ref** — `search_symbol` accepts a `ref`
   and cannot honour it (`app/adapters/bitbucket/client.py`), and the client filters
   project/repo client-side because the query DSL is unverified. A "not referenced in
   source" claim built on an unscoped substring search over the default branch is
   materially weaker than the constant-pool analysis it would replace. Registering it at
   `STRONG` would overclaim, and `STRONG` is the tier that is permitted to clear.
2. The pipeline already does the right thing without it. With no Tier 1/2 rule satisfied
   and no hard blocker, `determine()` consults the adjudicator, which can propose
   `NOT_AFFECTED` at `STRONG` *and already requires the refute pass to confirm it*. The
   path exists; it needs evidence, not a new rule.

`file(repo, path, ref)` **does** honour a ref, so reading the implicated types at the exact
commit is possible and is the stronger source signal. Prefer it over search where the
class-to-path mapping can be guessed, and treat search as the fallback.

### R5 — The adjudicator prompt must be rebuilt

This is the step most easily missed. `_build_prompt` (`app/adapters/llm/client.py`) sends
`provenance_verdict`, `class_present`, `referenced`, `reference_scan_conclusive` and
`escape_hatches` — all five artifact-derived. Under D1 every one of them is absent, so the
model receives a near-empty evidence object and should abstain, which routes everything to
human review. The automation would appear to run and decide nothing.

The prompt must carry source evidence instead: the implicated types from
`rootCauses[].listOfPaths`, which of them appear in the repository at the assessed commit,
the matching file paths and snippets, the dependency's declaration site (direct vs
transitive, which `iq.remediation()` already returns), and the repo/commit the evidence was
read at. It stays blind to CVSS, EPSS and KEV — that is deliberate and does not change.

Abstention stays first-class. If source lookup produced nothing for a CVE, the honest input
is "no source evidence", and `Confidence.INSUFFICIENT` routing to a human is the correct
outcome — not a clear.

### R6 — Scheduled review (D4)

**Configuration**, admin-set and audited. Behaviour tunables live in the database, not the
environment (`app/config.py`'s own doctrine), and this is a decision the team makes and
must be able to show an auditor.

| Field | Type | Notes |
|---|---|---|
| `cron_expression` | text | Standard 5-field cron. Needs a pinned parser — `croniter`. Validated on save; an invalid expression is rejected at the API, never stored |
| `scope_mode` | enum | `all_applications` \| `selected` |
| `patterns_json` | JSON list | Glob patterns matched against the IQ application id — `app1_test`, `app2*`. Ignored when `scope_mode` is `all_applications`. JSON list, not an array column (SQLite portability) |
| `enabled` | bool | Off by default. A schedule that starts running the moment it is saved gives no chance to check the scope first |
| `max_per_run` | int | Cap on assessments raised per tick. A bare `*` on first run would otherwise raise hundreds, each costing N IQ calls plus two adjudicator calls per finding |
| `last_run_at` / `next_run_at` | timestamp | Persisted, so a restart neither double-fires nor skips a window |
| `watermark` | timestamp | The newest indexed scan already considered. The tick queries `sbom_data` for records after it |
| `updated_by` / `updated_at` | text / timestamp | Who changed the schedule, for the audit trail |

Matching is `fnmatch` against the application id, **case-sensitive** — IQ application ids
are case-sensitive and a case-insensitive match would quietly widen the scope. The admin
screen should show which application ids currently match before the schedule is saved; a
glob whose blast radius is invisible until it fires is the wrong shape for something that
raises determinations.

**Scheduler.** An in-process `asyncio` task on the FastAPI lifespan, not a second
container: SQLite allows one writer and the deployment is single-replica. One tick at a
time, never overlapping; a tick that is still running when the next is due is skipped and
recorded, not queued.

**Three things the schedule collides with**, all needing an explicit answer:

1. **`docs/design.md` says "Intake is on-demand only."** Cron-started *review* is not
   auto-renewal of determinations (CLAUDE.md rule 4 stands untouched), so it is compatible
   in substance — but that sentence has to be rewritten rather than quietly contradicted.
2. **Who is the requester?** `Assessment.requester` drives My Assessments and is what
   separation of duties is keyed on (`assert_may_commit_own_determination`). An auto-raised
   assessment has no human requester. **Decision: a synthetic `system:scheduler`
   requester, plus a new `Assessment.origin` column (`manual` \| `scheduled`) surfaced in
   the queue and on the detail screen.** Separation of duties then does not constrain who
   approves an auto-raised assessment — correctly, because its purpose is that the person
   who asked for a clear is not the person who grants it, and here nobody asked. That is
   only acceptable if it is *visible*, which is what `origin` is for. Attributing the
   assessment to the admin who created the schedule was rejected: it would bar one
   arbitrary person from approving and give the appearance of a control without the
   substance.
3. **Duplicate work.** A tick must skip any (application_id, report_id) that already has a
   live assessment. Not a unique constraint — a reassessment after the 7-day expiry is a
   legitimate second row — so the check is "skip if an unexpired assessment exists".

### R7 — AI provider configuration (D3)

The `Adjudicator` Protocol already isolates this; `BedrockAdjudicator` is one
implementation of it. A second implementation against the Anthropic API sits beside it,
and `app/adapters/factory.py` selects one.

| Setting | Purpose |
|---|---|
| `ai_provider` | `bedrock` \| `anthropic` \| `fake` |
| `ai_model_id` | Replaces `bedrock_model_id`, which stays as a deprecated alias |
| `ai_base_url` | The endpoint, for a gateway or proxy |
| `ai_api_key` | `SecretStr`. Unused by the Bedrock path, which uses the IAM role |
| `ai_max_tokens`, `ai_timeout_seconds` | Already hardcoded at 1024 / 30s |
| `aws_region`, `bedrock_endpoint_url` | Unchanged, Bedrock path only |

Credentials and endpoints stay in the environment, never the database — a token in the
database appears in backups and in any settings dump.

**One thing to confirm at work.** "Claude Enterprise" is a seat-based plan on claude.ai and
does not itself expose a completions API. Programmatic access comes from the Anthropic API
(an API key), or from Bedrock/Vertex. Whichever of those the work environment actually
grants is what `ai_provider` selects — which is the point of making it a setting rather
than a code path. Worth confirming which one the enterprise agreement covers before the
second adapter is written, since it determines whether anything needs writing at all.

## Still unverified

Carried forward, none of it resolvable on this host:

- Whether IQ's vuln lookup returns reachability at all. `Tier3Signals.reachable_with_call_path`
  has no source anywhere — not on `RawReport`, `PolicyViolation` or `VulnDetail`, and not in
  the fake's shape. One real response settles it. Until then the hard blocker reads `None`,
  which deliberately does not block.
- The real `sbom_data` mapping: field names, whether SCM data is present per scan, whether
  the scan identifier matches IQ's report id, and what the indexing timestamp is called.
- Bitbucket DC's code-search response shape and query DSL.
- Whether the enterprise AI agreement provides an API-key path, a Bedrock path, or neither.
