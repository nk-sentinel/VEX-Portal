# Source-only review — implementation plan

Derived from `docs/requirements/elk-driven-intake.md` (decisions D1–D4). Nothing here is
built yet. Ordered so that each phase leaves the portal working: no phase depends on a
later one, and the artifact flow keeps running until phase 3 switches it off.

Current state: `feat/evidence-foundation` at `3e5c0fe`, 606 backend tests, 346 Karma specs.

## Dependency order

```
 P0  verify at work ──────────────┐  (blocks P2; everything else can start)
                                  │
 P1  AI provider config ──────────┼───────────────┐
                                  │               │
 P2  ELK: SCM fields + lookup ────┤               │
                                  ▼               │
 P3  admission + registry switch ─────────────────┤
                                  │               │
 P4  source collector ────────────┤               │
                                  ▼               ▼
 P5  adjudicator prompt ◀─────────────────────────┘
                                  │
 P6  server-side URL parsing ─────┤
                                  ▼
 P7  scheduler + config + screen
```

## P0 — Verify at work (blocks P2)

Four answers, none obtainable on shadowlab. Each one changes code if it comes back
differently than assumed.

| Question | Assumed | If wrong |
|---|---|---|
| Does `sbom_data` carry SCM per scan? | yes — repo URL, commit, branch | the whole decision needs revisiting; no source coordinates, no source analysis |
| What identifies a scan in the index? | IQ's report id (`iq/client.py:299` sets `scan_id=report_id`) | the lookup needs IQ's real scan id, found somewhere in the report body |
| What is the indexing timestamp field? | assumed to exist | the scheduler needs a different watermark, e.g. a monotonic doc id |
| Does IQ's vuln lookup return reachability? | unknown | if yes, `reachable_with_call_path` becomes populatable and the hard blocker starts firing |

One real `_search` response and one real vuln-lookup response answer all four. Capture both
as fixtures.

## P1 — AI provider configuration (D3)

| File | Change |
|---|---|
| `app/config.py` | `ai_provider`, `ai_model_id`, `ai_base_url`, `ai_api_key: SecretStr`, `ai_max_tokens`, `ai_timeout_seconds`. Keep `bedrock_model_id` as a deprecated alias so no existing `.env` breaks. Extend `_real_mode_needs_endpoints` to require what the selected provider needs |
| `app/adapters/llm/anthropic.py` | New `AnthropicAdjudicator`, same `Adjudicator` Protocol, same forced-tool-call contract, same error taxonomy (`UpstreamTimeout` / `UpstreamResponseError` / `UpstreamUnavailable`) |
| `app/adapters/factory.py` | Select on `ai_provider`; the Bedrock branch keeps its current behaviour exactly |
| `.env.example` | The new block, with the Bedrock values as the commented default |

Only write the Anthropic adapter once P0 says the enterprise agreement provides an API-key
path. If it is Bedrock after all, this phase is config-only and the second adapter is never
needed.

Verify: the existing adjudicator tests must pass unchanged against `ai_provider=bedrock`.
That is the regression bar for this phase.

## P2 — ELK: SCM fields and the lookup (R2)

| File | Change |
|---|---|
| `app/adapters/protocols.py` | `ScanRecord` gains `repository_url: str \| None`, `commit_sha: str \| None`, `branch: str \| None`, `indexed_at: datetime \| None`. Add `scans_since(since, limit)` to the `ScanArchive` Protocol for the scheduler |
| `app/adapters/elk/client.py` | Parse the new fields; implement `scans_since`. Keep "zero hits is absence, not an error" |
| `app/config.py` | `fake_elk_url`, so ELK stops being the one adapter with no fake |
| `fakes/elk/` | A fifth fake exposing `_search`, with the real response captured in P0 as its fixture |
| `fakes/data/elk.json` | Scan records for the sample applications, SCM fields populated |

ELK is currently the only adapter not exercised over real HTTP against a running fake
(`httpx.MockTransport` only). It is about to become load-bearing for admission, so it
should be held to the same bar as the other four.

Verify: ELK round-trips against a live fake like IQ/JFrog/Bitbucket/Bedrock do.

## P3 — Admission and the rule registry (R3, R4)

The switch-over. Both halves land together or the portal decides nothing.

| File | Change |
|---|---|
| `app/provenance/fingerprint.py` | A set-vs-set comparison beside the existing artifact `compare()`: report component sha1s vs index component sha1s, same `Verdict` vocabulary, `INSUFFICIENT_DATA` still refused |
| `app/services/admission.py` | Four checks (report → scan record → report/index agreement → source resolvable). New `ScanRecordUnavailable` and `SourceUnresolvable`; `ProvenanceMismatch` is reused for check 3. `AdmittedRequest` carries `ScanRecord` instead of artifact bytes + `Inventory` |
| `app/rules/registry.py` | `SOURCE_ONLY_RULES` = the four Tier 3 rules. Document *why* the artifact rules are excluded, in the same voice as `PENDING_EVIDENCE` — they return `UNANSWERABLE` with no artifact, and one `UNANSWERABLE` poisons every finding |
| `app/evidence/pack.py` | `EvidencePack` becomes buildable without artifact bytes: `provenance` from the set comparison, source evidence in place of `class_present` / `referenced` / `reference_scan_conclusive` |
| `app/api/assessments.py` | `artifact_coordinates` becomes optional in the request schema. `Assessment.artifact_ref` is already nullable |
| `web/.../new-assessment.*` | Drop the artifact type chips and the coordinates field. The hard-stop callout stays — check 3 still produces it |

The one invariant to test explicitly: with the source-only registry, a finding with no hard
blocker and a fix available must reach the adjudicator, **not** `NEEDS_REVIEW`. That is the
assertion that catches a stray registered artifact rule, which is the failure mode that
would make the whole automation silently inert.

Keep the artifact code. `app/artifact/*`, `app/provenance/fingerprint.py::compare` and the
three unregistered rules stay with their tests — D1 is a pause, not a deletion, and
reinstating the artifact later is then a registry edit rather than a rebuild.

## P4 — The source collector (R4)

| File | Change |
|---|---|
| `app/services/collection.py` | Replace the artifact fetch with source collection. Repo and commit come from `ScanRecord`, falling back to `iq.source_control()` for the repo and a requester-supplied commit. Per-CVE failure still means that finding is inconclusive, never clear |
| `app/adapters/bitbucket/client.py` | No change needed, but prefer `file(repo, path, ref)` — which honours the ref — over `search_symbol`, which cannot |
| `app/repos/models.py` | New `Evidence.collector` values: `elk_scan_record`, `source_presence` |

Resolution order per implicated class path:

```
org/apache/commons/text/StringSubstitutor.class
        │
        ├─▶ guess source paths:  src/main/java/org/apache/commons/text/StringSubstitutor.java
        │        file(repo, path, commit)  ──▶ found: strongest signal, read at the commit
        │                                  ──▶ 404:  fall through
        └─▶ search_symbol(repo, "StringSubstitutor", branch)
                 unscoped to the commit — weaker, record it as such
```

Record which route produced each hit. "Read at the assessed commit" and "found by an
unscoped index search" are different strengths of evidence and the adjudicator is entitled
to know which it is looking at.

## P5 — The adjudicator prompt (R5)

| File | Change |
|---|---|
| `app/adapters/llm/client.py` | `_build_prompt` carries source evidence: implicated types, which were found and by which route, file paths and snippets, direct-vs-transitive from `iq.remediation()`, and the repo + commit the evidence was read at. Still blind to CVSS/EPSS/KEV |
| `app/services/adjudication.py` | No structural change — abstention and the refute pass already behave correctly. Confirm "no source evidence at all" presents as absence, so the model abstains rather than inferring absence of use |

The test that matters: an evidence pack with **no** source hits must not produce a clear. It
is the same property the artifact flow protects with `reference_scan_conclusive` — absence
of evidence is not evidence of absence — and it needs its own test at this layer because
the anti-check that enforced it lived on `t2-not-referenced`, which is no longer registered.

## P6 — Server-side report URL parsing (R1)

| File | Change |
|---|---|
| `app/schemas/assessments.py` | Accept `report_url`; derive `application_id` + `report_id`. Keep accepting the explicit pair for one release so nothing breaks mid-deploy |
| `app/services/` | A small parser module: the one `#/applicationReport/{app}/{report}` shape, rejecting anything else with a message naming what was expected |
| `web/.../assessments.model.ts` | Delete `extractReportId` — the server owns this now |
| `web/.../new-assessment.*` | One URL field replaces the typed application id and report fields |

This also removes the typed application id that `docs/decisions/intake-entitlement.md`
introduced, and gives the scheduler the same parsing path as the form.

## P7 — Scheduler (R6)

| File | Change |
|---|---|
| `alembic/versions/0004_*.py` | `schedule_config` per R6's table. `Assessment.origin` (`manual` \| `scheduled`), defaulting to `manual` |
| `app/repos/models.py` | The model, with the column docstrings carrying the reasoning |
| `app/services/scheduling.py` | Tick: resolve due schedules → `elk.scans_since(watermark)` → `fnmatch` the application ids → skip any with a live assessment → raise up to `max_per_run`, attributed to `system:scheduler` → advance the watermark. Never overlapping; a still-running tick skips the next window and records that it did |
| `app/main.py` | Start and stop the task on the lifespan. Only when a schedule is enabled |
| `app/api/admin.py` | CRUD under `manage_rules`, or a new `manage_schedule` capability if scheduling should be separable from rule administration. Validate the cron expression on save; preview the matching application ids before it is stored |
| `app/services/authorization.py` | The new capability, if that route is taken |
| `requirements.txt` | `croniter`, pinned |
| `web/.../rules-thresholds` or a new screen | Cron input, scope toggle, pattern list, the matching-ids preview, enable switch, last and next run |
| `web/.../review-queue`, `assessment-detail` | Show `origin`, so an auto-raised assessment is visibly distinct |

Separation of duties does not apply to a `system:scheduler` assessment — there is no human
requester to exclude. That is correct but must be visible, which is the whole purpose of
`origin`. Test it both ways: an approver may commit a scheduled assessment, and may still
not commit one they raised themselves.

## What this costs in tests

| Phase | Expect |
|---|---|
| P1 | Existing adjudicator tests pass unchanged; new ones for the second provider |
| P2 | ELK tests move from `MockTransport` to a live fake |
| P3 | Admission tests largely rewritten; the artifact-rule tests stay but no longer run through the default registry |
| P4 | Collection tests rewritten around source, not bytes |
| P5 | New: no-source-evidence must not clear |
| P6 | `extractReportId`'s Karma tests move to the backend |
| P7 | New throughout, including the two separation-of-duties cases |

The suite will shrink before it grows. The artifact tests are not deleted — they stop being
exercised by the default path, and that difference should be obvious in the registry module
rather than discovered later.
