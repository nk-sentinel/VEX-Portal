# VEX Portal — product

Written for someone deciding whether to adopt, fund or audit this, not for someone editing
it. Vocabulary: `docs/naming.md`. Architecture: `docs/design.md`. As-built inventory:
`docs/implemented.md`.

Describes the product including the decisions of 2026-10-19 (source-only evidence,
AI adjudication as the normal path, scheduled review). Sections marked **planned** are
specified but not yet built — `docs/implementation/source-only-review.md` has the order.

## The problem

Software composition analysis reports every known vulnerability in every dependency. Most
of those findings do not apply to the application that ships them: the vulnerable class is
not on the classpath, the vulnerable method is never called, the attack needs a
configuration the app does not use. An application team has no realistic way to work
through hundreds of findings at this depth, so the backlog grows, the real findings sit in
it, and the ones that do not apply get cleared on judgement with no record of why.

The portal does that analysis, records the evidence behind every answer, and escalates
anything it cannot answer — rather than clearing it.

## What it produces

A **determination**: a statement that a specific vulnerability does or does not affect a
specific application, in CycloneDX VEX vocabulary, with the evidence attached.

| Outcome | Meaning | What happens |
|---|---|---|
| `NOT_AFFECTED` | Not exploitable here, with a VEX justification | Recorded in Nexus IQ for 7 days; the finding stops blocking the build |
| `AFFECTED` | Exploitable; remediation needed | Nothing suppressed; stays with the app team |
| `NEEDS_REVIEW` | The portal will not answer this | Routed to a human reviewer with everything it collected |
| `RISK_ACCEPTANCE_REQUIRED` | No fix exists | The app team takes the evidence package to their risk manager. **The finding stays open** |

Four deliberate properties, each of which costs something:

- **Determinations expire after 7 days and are never auto-renewed.** All branches scan into
  one IQ application, so a determination against one branch cannot be assumed valid for
  another that may reach a vulnerable method the first does not. The cost is repeated work;
  the alternative is a clear that outlives the evidence for it.
- **"No fix available" is never a Not Affected determination.** Accepted risk must stay
  visible, and a hand-off is not a resolution.
- **The portal can say it does not know.** The adjudicator can abstain, and an abstention
  routes to a human. Without that path the "unsure" bucket stays silently empty and
  ambiguous cases get forced into confident-looking answers.
- **One class of evidence may never clear a finding.** Severity, exploit-prediction scores
  and known-exploited status can raise urgency or escalate to a human. They can never
  justify "not affected" — they are facts about the vulnerability, not about this
  application.

## Who uses it

| Role | What they do |
|---|---|
| **Requester** (app team) | Raises an assessment by pasting a Nexus IQ report URL |
| **Reviewer** (AppSec) | Works the review queue; recommends an outcome |
| **Approver** (AppSec lead) | Commits a determination. Cannot commit one they raised themselves |
| **Risk manager** | Owns the risk-acceptance queue where no fix exists |
| **Auditor** | Read-only across the queue, the evidence and the dashboard |
| **Admin** | Rule toggles, thresholds, the review schedule |

Permissions are capability-based: every call site checks a capability, never a role, so a
permission change is a one-line mapping edit rather than a hunt through the code. The full
matrix is in `docs/implemented.md`.

## How a request flows

```
   report URL
       │
       ▼
  ADMISSION   ──── refused ───▶  told what to fix, in one message
       │                         (purged report, unindexed scan,
       │                          mismatched build, missing commit)
       ▼
  COLLECT     Nexus IQ: vulnerability + remediation per CVE
              ELK:      the scan's SBOM, repo and commit
              Bitbucket: the implicated types at that commit
       │
       ▼
  DECIDE      hard blocker?  ─── yes ──▶  NEEDS_REVIEW   (never asked of the AI)
              no fix?        ─── yes ──▶  RISK_ACCEPTANCE_REQUIRED
              otherwise      ──────────▶  adjudicator, then an independent
                                          refute pass on any proposed clear
       │
       ▼
  OUTCOME     cleared → recorded in Nexus IQ, 7 days
              anything else → a human, with the full evidence trail
```

Admission is a gate, not a formality. It refuses a request whose report has purged, whose
scan is not in the index, whose source commit cannot be read, or — the hard stop — where
the scan report and the SBOM index describe different builds. Reasoning about the wrong
build produces a confident answer about software that was never scanned, which is worse
than no answer.

## What the automation is allowed to decide alone

This is the core control, and the 2026-10-19 decision changed it.

| | Before (artifact evidence) | Now (source evidence) |
|---|---|---|
| Deterministic clear, no AI | yes — binary inspection could prove a class absent | **no** |
| AI clear, confirmed by a refute pass | yes | yes |
| AI alone, unconfirmed | never | never |
| Severity / EPSS / known-exploited alone | never | never |

Evidence came from the built binary, where "this class does not ship" is provable. Evidence
now comes from source at the scanned commit, which is strong but defeasible — reflection,
service loading and dependency injection all reach code that source inspection does not
show. So **every clear now goes through the AI adjudicator and an independent second pass
that tries to refute it.** Disagreement between the two routes to a human.

The adjudicator is deliberately constrained. It is handed a fixed evidence package and
asked to classify it through a closed enumeration — never asked an open question, never
able to go looking for more. It is not shown severity, exploit-prediction or
known-exploited data, so it cannot be talked into a clear by a low severity score; those
signals are checked separately and earlier, and a blocked finding never reaches it.

## Scheduled review (planned)

Today every assessment is raised by a person. The planned scheduler watches the SBOM index
and starts reviews as scans arrive, on a configurable cron expression, across all
applications or a glob-matched selection (`app1_test`, `app2*`).

Two things worth knowing before enabling it:

- **An auto-raised assessment has no human requester.** The separation-of-duties rule —
  the person who asks for a clear is not the person who grants it — has nobody to exclude.
  Auto-raised assessments are therefore marked as such everywhere they appear, so the
  absence of that control is visible rather than implicit.
- **Scope is capped per run.** A broad pattern on its first run would otherwise start
  hundreds of reviews at once, each one costing API calls against Nexus IQ and the model.

## Audit position

- Every state transition writes an append-only audit entry: who, what, when, against which
  finding.
- The evidence behind each determination is **snapshotted as values**, never as a pointer
  back into Nexus IQ, the SBOM index or the source server. IQ's reports purge on a short
  window; an audit trail that depends on another team's retention policy is not a trail.
- The rule trace is kept per finding: which rules ran, what each concluded, and what the
  adjudicator was given. A determination can be reconstructed years later.
- Outcomes use the CycloneDX VEX enumerations verbatim. "Recorded in CycloneDX VEX format"
  is a stronger sentence to an auditor than "categorised using our internal scheme".
- The portal does not use the word "waiver" anywhere a user can see, because audit and
  management read it as suppressing a real finding. What is recorded is a determination
  that a vulnerability does not apply, with its evidence.

## Limits, stated plainly

- **Nothing proves the scanned binary was built from the assessed source.** The commit
  identifies the source; under source-only evidence there is no artifact to fingerprint.
  Report-to-index agreement is checked instead, which catches a mismatched build but not a
  tampered one.
- **Source analysis is weaker than binary analysis.** It is why every clear now requires
  the adjudicator and a refute pass.
- **Reachability from Nexus IQ is unconfirmed.** Whether IQ's vulnerability lookup returns
  call-path reachability is not yet established; until it is, that hard blocker reads
  "never checked" and does not block.
- **One application instance, one database.** Deliberate: the workload does not justify a
  managed database, and the schema is kept portable so that decision stays reversible.
  Rolling deploys take brief downtime.
- **Seven-day expiry means recurring work.** A determination that lapses must be raised
  again against a fresh scan.
