# Source-based review — implementation plan

From `docs/requirements/elk-driven-intake.md`. Nothing built yet. Base: `9dd3910`,
606 backend tests, 346 Karma specs.

Ordered so each phase leaves the portal working. The artifact flow keeps running until P5.

```
 P0 verify at work ──┐
                     ├──▶ P1 ELK ──┐
 P2 source fetch ────┤             ├──▶ P5 admission ──┐
                     │             │                   │
                     └──▶ P3 script pass ──▶ P4 rules ─┤
                                                       ├──▶ P6 prompt
                                                       │
                     P7 URL parsing ───────────────────┤
                                                       └──▶ P8 scheduler
                     P9 AI knobs (independent, any time)
```

## P0 — Verify at work

| Question | Assumed | If wrong |
|---|---|---|
| Does `sbom_data` carry SCM per scan? | repo URL, commit, branch | no source coordinates — the whole flow needs rethinking |
| What identifies a scan in the index? | IQ's report id (`iq/client.py:299`) | the lookup needs IQ's real scan id |
| Indexing timestamp field? | assumed present | the scheduler needs another watermark |
| Does `rootCauses` carry a method name? | class paths only today | the method-level check in R1 is not buildable; type-level only |
| Does the vuln lookup return reachability? | unknown | if yes, `reachable_with_call_path` starts hard-blocking |
| Does `sbom_data` carry per-component scope? | unknown — CycloneDX has `required`/`optional`/`excluded` | if yes, it corroborates `t1-not-shipped` from an independent system (R1.1) |
| Is `affected_version_range` machine-parsable? | syntax unconfirmed | decides whether R1.2 is buildable at all |
| Bitbucket archive endpoint path? | `/rest/api/latest/.../archive?at=&format=zip` | fall back to per-file `raw` reads, which already honour `at` |

One real `_search` response, one real vuln-lookup response, one archive request. Capture all
three as fixtures.

## P1 — ELK

| File | Change |
|---|---|
| `app/adapters/protocols.py` | `ScanRecord` += `repository_url`, `commit_sha`, `branch`, `indexed_at`. `ScanArchive` += `scans_since(since, limit)` |
| `app/adapters/elk/client.py` | Parse them; implement `scans_since`. Zero hits stays absence, not an error |
| `app/config.py` | `fake_elk_url` |
| `fakes/elk/`, `fakes/data/elk.json` | Fifth fake, `_search` over scan records for the sample apps |

Verify: ELK round-trips over real HTTP against a live fake, like the other four.

## P2 — Source fetch

| File | Change |
|---|---|
| `app/adapters/protocols.py` | `SourceRepository` += `archive(repo, ref) -> bytes` |
| `app/adapters/bitbucket/client.py` | Implement it. Keep `search_symbol` for reviewer context |
| `fakes/bitbucket/main.py` | Archive route zipping the canned tree |
| `app/source/tree.py` | New: walk the zip, index paths by language, enforce a size cap. Mirrors `app/artifact/inventory.py` |

One fetch per assessment. Nothing in the per-CVE loop touches the network.

## P3 — The script pass

The core of this work. `app/source/` mirrors `app/artifact/`: fetch bytes once, analyse
offline, standard library only.

| File | Purpose |
|---|---|
| `app/source/tree.py` | The archive walker (P2) |
| `app/source/imports.py` | Which packages first-party source imports. Java `import` statements, with the package-level and wildcard cases |
| `app/source/usage.py` | Where a type is referenced, and where a named method is called on it. Line + snippet per hit |
| `app/source/hatches.py` | Escape hatches: `Class.forName`, `ServiceLoader`, DI annotations, SpEL, JNDI, string-built class names. Any hit marks the scan inconclusive |
| `app/source/manifests.py` | Dependency declarations per build file: Maven `pom.xml` scopes, Gradle `build.gradle`/`.kts` configurations, and whether a shading or fat-jar plugin is in play. Feeds `t1-not-shipped` (R1.1) |
| `app/source/scan.py` | Assembles the above into a `SourceScan` with an `is_conclusive()` in the same shape as `ReferenceScan` |

Per CVE, the script produces:

```
cve, purl
  ├─ is_transitive        ← iq.remediation()       (branch on this first)
  ├─ declared_scopes      ← manifests.py          per build file; unanimity required
  ├─ packaging_repackages ← manifests.py          shade / assembly / shadow present?
  ├─ package_imported     ← imports.py            (meaningless if transitive)
  ├─ types_referenced     ← usage.py              [(path, line, snippet), ...]
  ├─ method_called        ← usage.py              None if IQ gave no method name
  └─ conclusive           ← hatches.py            False ⇒ nothing above is absence
```

The three tests that matter most:

- A **transitive** dependency with no first-party import must **not** resolve to non-use.
- An **inconclusive** scan must **not** resolve to non-use.
- A component declared test-scope in one module and compile-scope in another must **not**
  resolve to not-shipped.

All three are the failure modes that would clear live vulnerabilities on no evidence.

## P4 — Rules

| File | Change |
|---|---|
| `app/rules/tier1.py` | New `NotShipped` (`t1-not-shipped`, R1.1) — `PROOF`, `CODE_NOT_PRESENT`, with R1.1's four anti-checks and its verdict table. **`INAPPLICABLE`, never `UNANSWERABLE`,** for a transitive component or an unrecognised build tool: `UNANSWERABLE` would route every finding in every non-Maven/Gradle repo to a human |
| `app/rules/tier2.py` | New `PackageNotImported`, `TypeNotReferenced`, `MethodNotCalled` — all `STRONG`, all carrying the anti-check, all `UNANSWERABLE` when the input is absent rather than guessing |
| `app/rules/registry.py` | `ACTIVE_RULES` = `t1-not-shipped` + the three Tier 2 source rules + the four Tier 3 rules. Artifact rules move out, documented like `PENDING_EVIDENCE`: they return `UNANSWERABLE` with no artifact, and one `UNANSWERABLE` forces the whole finding to a human — leaving them registered would make the automation inert |
| `app/evidence/pack.py` | `EvidencePack` built from `SourceScan` + `ScanRecord` instead of artifact bytes; `provenance` from the report↔index comparison |
| `app/rules/engine.py` | No structural change. Tier 2 already sets `requires_second_confirmation`, which is what routes to the AI |

Two invariants worth their own tests. A finding with no hard blocker and a fix available
must reach the adjudicator, **not** `NEEDS_REVIEW` — that is what catches a stray
artifact rule left in the registry, the failure mode that would make the automation
silently inert. And `t1-not-shipped` answering `INAPPLICABLE` must leave routing unchanged:
a repo with no recognised build file still gets the full Tier 2 plus adjudicator path.

Tier 3 rules, hard blockers and the no-fix path are untouched.

Artifact code stays with its tests — `app/artifact/*`, `provenance/fingerprint.py::compare`
and the now-unregistered rules. Reinstating the artifact later is a registry edit.

## P5 — Admission

| File | Change |
|---|---|
| `app/provenance/fingerprint.py` | Set-vs-set comparison beside the artifact `compare()`: report sha1s vs index sha1s, same `Verdict` vocabulary, `INSUFFICIENT_DATA` still refused |
| `app/services/admission.py` | Four checks per R5. New `ScanRecordUnavailable`, `SourceUnresolvable`; `ProvenanceMismatch` reused for check 3. `AdmittedRequest` carries `ScanRecord` + the source archive |
| `app/api/assessments.py` | `artifact_coordinates` optional, then removed. `Assessment.artifact_ref` is already nullable |
| `web/.../new-assessment.*` | Drop the artifact chips and coordinates field. The hard-stop callout stays — check 3 produces it |

## P6 — Adjudicator prompt

| File | Change |
|---|---|
| `app/adapters/llm/client.py` | `_build_prompt` carries the script's findings, *why* anything was inconclusive, call-site snippets, direct-vs-transitive, affected range, repo + commit. Still blind to CVSS/EPSS/KEV |
| `app/services/adjudication.py` | No structural change. Confirm "no source evidence" presents as absence so the model abstains |

Test: an evidence pack with no source hits and no explanation must not clear. The anti-check
that protected this lived on `t2-not-referenced`; it now needs its own test at this layer.

## P7 — Server-side URL parsing

| File | Change |
|---|---|
| `app/services/report_url.py` | Parse `#/applicationReport/{app}/{report}`. Anything else is a request error naming what was expected |
| `app/schemas/assessments.py` | Accept `report_url`; keep the explicit pair for one release |
| `web/.../assessments.model.ts` | Delete `extractReportId` — the server owns this |
| `web/.../new-assessment.*` | One URL field replaces the typed app id and report fields |

Removes the typed application id from `docs/decisions/intake-entitlement.md`, and gives the
scheduler the same parsing path as the form.

## P8 — Scheduler

| File | Change |
|---|---|
| `alembic/versions/0004_*.py` | `schedule_config` per R7; `Assessment.origin` defaulting to `manual` |
| `app/services/scheduling.py` | The tick, per R7. Never overlapping |
| `app/main.py` | Start/stop on the lifespan, only when a schedule is enabled |
| `app/api/admin.py` | CRUD under a new `manage_schedule` capability. Validate the cron on save; preview matching app ids before storing |
| `app/services/authorization.py` | The new capability |
| `requirements.txt` | `croniter`, pinned |
| `web/` | Schedule screen: cron input, scope toggle, pattern list, match preview, enable switch, last/next run. `origin` column in the queue and detail |

Test both separation-of-duties cases: an approver **may** commit a scheduled assessment, and
**may not** commit one they raised themselves.

## P9 — AI config

`ai_max_tokens`, `ai_timeout_seconds`, `ai_enabled` into `app/config.py`; `bedrock_model_id`
aliased as `ai_model_id`. `ai_enabled=false` runs script-only and routes the rest to humans —
worth having for the first rollout, to measure what the script resolves before the model is
in the loop.

## Test impact

| Phase | Expect |
|---|---|
| P1 | ELK moves from `MockTransport` to a live fake |
| P2–P3 | Largest new surface; `app/source/` tests mirror `app/artifact/`'s |
| P4 | Artifact rule tests stay but leave the default registry |
| P5 | Admission tests largely rewritten |
| P6 | New: no-source-evidence must not clear |
| P7 | `extractReportId`'s Karma tests move to the backend |
| P8 | New throughout |

The suite shrinks before it grows. Artifact tests are not deleted — they stop being on the
default path, and that should be visible in the registry module, not discovered later.
