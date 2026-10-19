# ELK-driven intake — target flow vs what is built

Stated 2026-10-19. Compares the intended flow against the implementation at `2e3b543`
plus the entitlement removal.

## The target flow

1. User logs in
2. Raises a request by passing **a Nexus IQ report URL**
3. Automated review starts
4. An Elastic index (`sbom_data`) holds, pushed post-scan: SBOM data + CVE info + SCM info
5. From the report URL, query that index to get **the Bitbucket URL + commit id**
6. Use those to perform reachability / exploitability analysis
7. Per CVE, fetch vuln info **and reachability/exploitability** from IQ's vuln lookup API
8. A cron job periodically reads the index and starts reviews automatically in the background

## Sync status

| # | Step | State | Detail |
|---|---|---|---|
| 1 | Login | **Built** | Local (argon2) + LDAP providers, signed session cookie, configurable TTL |
| 2 | Report URL intake | **Half** | The URL is parsed **client-side** (`extractReportId`, last path segment) and the backend only ever receives `report_id`. The app id in the same URL is discarded, which is why it is now a separate typed field |
| 3 | Automated review starts | **Built** | Synchronously, inside the `POST` request — see "Where this diverges" |
| 4 | `sbom_data` index | **Partial** | `ElkHttpClient.sbom_for_scan(scan_id)` exists but is **wired to nothing** — no caller anywhere. It returns `components` + `cve_ids` only; `ScanRecord` carries **no SCM fields**. Index default is `sbom-scans-*`, keyed on `scan_id`, not a report URL |
| 5 | URL → Bitbucket URL + commit | **Not built** | SCM today comes from IQ's `source_control(application_id)` (repo URL + branch) and the commit from the **artifact's** `git.properties`, or from the requester. Nothing resolves either from ELK |
| 6 | Reachability from source | **Divergent** | Tier 1/2 evidence is derived from the **JFrog artifact**, not source. Bitbucket symbol search is collected and stored, but **no rule reads it** — it is reviewer context only |
| 7 | Vuln info per CVE | **Built** | `IqClient.vulnerability()` returns CVSS, EPSS, KEV (tri-state), `rootCauses[].listOfPaths` |
| 7 | Reachability from vuln lookup | **Not available** | `Tier3Signals.reachable_with_call_path` is documented as having no source — not on `RawReport`, `PolicyViolation`, or `VulnDetail`, and absent from the fake's report shape. Needs confirming against real IQ |
| 8 | Cron-driven background review | **Not built** | No scheduler, no worker, no job table, no `BackgroundTasks` anywhere |

## Where this diverges from the built design, and what it costs

**The artifact is load-bearing today; the target flow drops it.** Tier 1 — the only tier
that may clear a finding on its own — is entirely artifact-derived: `t1-class-absent` and
`t1-component-absent` both read the shipped JAR/WAR. The provenance admission check also
compares artifact hashes against the report's component hashes. Replacing the artifact with
`(bitbucket_url, commit)` means:

- **No Tier 1 proof is reachable.** Source evidence is Tier 2 (`code_not_reachable`), which
  by rule needs the AI refute pass and can never auto-clear alone. The deterministic,
  no-AI-no-human majority path the design is built around disappears.
- **No provenance check.** The commit proves which source was built; it does not prove the
  scanned artifact matches it. Admission loses its hard stop.
- **Source evidence is weaker than what exists.** Constant-pool analysis reads compiled
  reality and catches what grep misses; that was the deliberate reason the artifact won
  over source in the original design (`docs/design.md`, Tier 2 item 6 vs 7).

This is a decision, not a defect — but it is a change to **what the portal is allowed to
decide automatically**, not just to where the inputs come from. Three options:

1. **Keep the artifact, add ELK as the SCM source** — smallest change. ELK supplies
   `bitbucket_url` + commit (replacing IQ `source_control` and the `git.properties` read),
   and the artifact keeps supplying Tier 1. The report URL can then carry everything.
2. **Source-only evidence** — accept that every finding needs the adjudicator or a human,
   and say so explicitly in the tier table. Requires promoting source evidence from
   reviewer context to a registered rule.
3. **Both, tiered** — artifact when available, source when not, with the tier the evidence
   earns. Most faithful to the existing model; most work.

**Cron intake collides with three things.** Worth settling before building it:

- `docs/design.md` states "Intake is on-demand only." Cron-started *review* is not
  auto-renewal, so it is compatible in substance — but the sentence needs rewriting.
- **Who is the requester?** `Assessment.requester` drives My Assessments, and separation of
  duties (`assert_may_commit_own_determination`) is keyed on it. An auto-raised assessment
  needs a synthetic requester, and then every approver may commit it — the requester ≠
  approver rule silently stops applying.
- **Single writer.** SQLite means the cron worker runs in the same process/container as the
  API, not a second one.

## Smallest next steps, in order

1. **Server-side report URL parsing** — recover *both* app id and report id from the URL, so
   intake is one pasted field again. Removes the typed app id the entitlement change added.
2. **Give `ScanRecord` its SCM fields and key the lookup on report id** — `repository_url`,
   `commit_sha`, `branch`. Verify against the real index mapping first; the current query
   shape is assumed, not confirmed.
3. **Wire ELK into `collect_evidence`** as the SCM source, then decide option 1/2/3 above.
4. **Confirm whether IQ's vuln lookup actually returns reachability** — one real response
   settles it and unblocks `reachable_with_call_path`.
5. **Cron last**, once the requester-identity question is answered.
