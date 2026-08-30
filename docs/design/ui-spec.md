# UI Specification — Exploitability Assessment Portal

Input document for UI design. Defines every screen, what it covers, and how the screens
relate. Layout and interaction only — no visual styling decisions here.

---

## 0. Rules that constrain every screen

**Never use the word "waiver" anywhere in the interface.** Not in labels, buttons, table
headers, tooltips, notifications, or exports. Audit and management read it as suppressing a
real finding. The interface says *determination*, *assessment*, *Not Affected*. The Nexus IQ
waiver is a backend implementation detail and must never surface.

**The interface must never imply that app context cleared a finding.** Exposure, criticality,
CVSS, EPSS and KEV are shown as *escalation* signals. They may explain why something was sent
to a human, never why something was cleared. Do not render them adjacent to a Not Affected
verdict in a way that reads as supporting it.

**Every Not Affected determination must show its evidence inline.** A verdict with no visible
basis is the failure mode this portal exists to prevent.

### Shared vocabulary

| Term | Never say |
|---|---|
| Exploitability Assessment | waiver request |
| Determination | waiver, exception |
| Not Affected | waived, suppressed, accepted |
| Affected | vulnerable, failed |
| Under Investigation | pending, unknown |
| Reassessment | renewal, extension |

### Status vocabulary and semantics

**Assessment states** (one per request, covering the whole IQ report):

| State | Meaning |
|---|---|
| `DRAFT` | Being filled in, not submitted |
| `ADMISSION` | Report / artifact / provenance checks running |
| `ADMISSION_FAILED` | Terminal. Requester must correct inputs and resubmit |
| `ANALYSING` | Collectors, rules and adjudicator running |
| `NEEDS_REVIEW` | One or more findings require a human |
| `AWAITING_APPROVAL` | Reviewer recommended; approver must commit |
| `COMPLETED` | All findings determined; determinations pushed to IQ |
| `EXPIRED` | 7 days elapsed. Requester must raise a reassessment |

**Finding outcomes** (many per assessment):

| Outcome | Icon | Meaning |
|---|---|---|
| Not Affected | ✓ | Cleared, with tier and justification shown |
| Affected | ✗ | Exploitable. Remediation required |
| Needs Review | ▲ | Routed to a human |
| Risk Acceptance Required | ⚑ | No fix available. Leaves the portal's flow entirely |

**Risk Acceptance Required is not a determination and must not be styled as one.** It is a
hand-off. The IQ violation stays open. Its visual treatment should read as "this left the
system", not "this is resolved".

---

## 1. Screen inventory

Nine routed screens plus one overlay component.

| # | Screen | Primary role | Route |
|---|---|---|---|
| 1 | Login / SSO landing | all | `/login` |
| 2 | New Assessment | Requester | `/assessments/new` |
| 3 | My Assessments | Requester | `/assessments` |
| 4 | Assessment Result | Requester | `/assessments/:id/result` |
| 5 | Review Queue | Reviewer, Approver | `/review` |
| 6 | Assessment Detail | Reviewer, Approver | `/review/:id` |
| 7 | Dashboard | Auditor, Management | `/dashboard` |
| 8 | Risk Acceptance Queue | Risk Manager | `/risk-acceptance` |
| 9 | Rules & Thresholds | Admin | `/admin/rules` |
| — | **Evidence Drawer** (overlay) | Reviewer, Approver | drawer over 5, 6, 8 |

### Navigation map

```
LOGIN (AD / SSO)
  │
  │  role-based landing
  │
  ├── Requester ────────► [3] MY ASSESSMENTS
  │                            ├──► [2] NEW ASSESSMENT ──┐
  │                            └──► [4] ASSESSMENT RESULT ◄┘
  │
  ├── Reviewer ─────────► [5] REVIEW QUEUE
  │   / Approver              ├──► ((EVIDENCE DRAWER))
  │                           └──► [6] ASSESSMENT DETAIL
  │                                     └──► ((EVIDENCE DRAWER))
  │
  ├── Auditor / Mgmt ───► [7] DASHBOARD
  │                           └──► [6] ASSESSMENT DETAIL (read-only)
  │
  ├── Risk Manager ─────► [8] RISK ACCEPTANCE QUEUE
  │                           └──► ((EVIDENCE DRAWER, read-only))
  │
  └── Admin ────────────► [9] RULES & THRESHOLDS
```

**Screens 5 and 6 are one component, differently scoped.** Review Queue is "all findings
filtered by state"; Assessment Detail is "findings where assessment = X". Same table, same
drawer, same keyboard model — one thing to build, one thing to learn.

**The Evidence Drawer is a right-hand side panel, not a modal.** Reviewers work down a list.
A modal dims the context and closing it loses your place; a drawer keeps the queue visible,
keeps filters alive, and lets the next finding load without closing anything. This is the
difference between reviewing forty findings in a sitting and reviewing fifteen.

---

## 2. Screen designs

### [1] Login / SSO landing

Minimal. AD-backed SSO redirect. Present only because unauthenticated users need somewhere
to land and because role resolution failures need a visible error.

**States**
- *Default* — product name, one "Sign in" action
- *Loading* — redirect in progress
- *Error* — authentication succeeded but no recognised role group. Message must say which
  groups grant access and who to contact, not "access denied"

---

### [2] New Assessment

Requester raises an assessment covering every open security finding in one IQ report.

```
┌─ New Exploitability Assessment ────────────────────────────────┐
│                                                                │
│  APPLICATION                                                   │
│   [ payments-api                                        ▾ ]    │
│   Only applications you can access in Nexus IQ are listed.     │
│                                                                │
│  NEXUS IQ REPORT URL                                           │
│   [ https://iq.../applicationReport/payments-api/38ef4d... ]   │
│   ✓ Report found · build stage · scanned 2026-08-29 14:02      │
│   ✓ 12 open security findings                                  │
│                                                                │
│  BUILD ARTIFACT                                                │
│   ( ) Binary   (•) Container image                             │
│   [ artifactory.../payments-api:1.14.2                    ]    │
│   ✓ Image found · 412 MB · 6 layers                            │
│   ⏳ Verifying artifact matches report…                         │
│                                                                │
│  CONTEXT                                                       │
│   Branch assessed        [ release/1.14              ]         │
│   Commit                 [ 4a9f1c2 ] ✓ matches git.properties  │
│   Why is this needed?    [ ................................ ]  │
│                                                                │
│  ────────────────────────────────────────────────────────────  │
│   Determinations last 7 days and are not renewed automatically.│
│                                    [ Cancel ]  [ Submit ]      │
└────────────────────────────────────────────────────────────────┘
```

**Elements**
- *Application* — searchable select, populated from Nexus IQ scoped to the user's own
  entitlement. If empty, the user has no IQ access and the form cannot proceed
- *Report URL* — text input, validated on blur. Resolves to app + report and shows scan stage,
  scan time and open finding count
- *Artifact type* — radio, binary or container image. Changes the placeholder and the
  validation performed
- *Artifact reference* — text input, validated on blur against JFrog
- *Provenance check* — runs after both report and artifact resolve. Async, may take seconds
- *Branch / commit* — text inputs, pre-filled from the report if IQ carries SCM metadata,
  otherwise entered by the requester and cross-checked against `git.properties`
- *Justification* — free text, required. Feeds the reviewer's context, not the rule engine
- *Submit* — disabled until all three admission checks pass

**Admission checks shown inline, each with its own state**

| Check | Pass | Fail message must say |
|---|---|---|
| Report retrievable | ✓ with scan metadata | Report not found or purged — IQ keeps build-stage reports 14 days. Re-scan and try again |
| Artifact retrievable | ✓ with size | Artifact not found at that coordinate |
| Artifact matches report | ✓ *n/n* components matched | How many matched, how many did not, and that this usually means the artifact is a different build |

**States**
- *Loading* — per-field inline spinners; the form stays usable while checks run
- *Empty* — no IQ applications accessible: explain the IQ entitlement requirement
- *Error* — an upstream system is unreachable: name which one. "IQ is unreachable" and
  "artifact not found" are different problems and must not share a message
- *Blocked* — provenance mismatch is a hard stop, not a warning. Show matched/unmatched counts
  and offer "Use a different artifact"

---

### [3] My Assessments

Requester's own requests. Assessment-level rows, not findings.

```
┌─ My Assessments ───────────────────────────── [ + New ] ───────┐
│  [ all ▾ ]  [ application ▾ ]                                  │
│ ───────────────────────────────────────────────────────────────│
│  ASM-2418  payments-api    ANALYSING      12 findings    2m ago│
│            ▓▓▓▓▓▓▓▓░░░░  collecting evidence 8/12              │
│ ───────────────────────────────────────────────────────────────│
│  ASM-2417  ledger-svc      COMPLETED      9 findings     1d ago│
│            ✓ 7 not affected  ✗ 1 affected  ⚑ 1 risk accept.   │
│            expires in 6 days                                   │
│ ───────────────────────────────────────────────────────────────│
│  ASM-2410  batch-runner    EXPIRED        4 findings     8d ago│
│            determination lapsed · [ Raise reassessment ]       │
│ ───────────────────────────────────────────────────────────────│
│  ASM-2409  auth-gateway    ADMISSION FAILED              9d ago│
│            artifact did not match report · [ Fix and resubmit ]│
└────────────────────────────────────────────────────────────────┘
```

**Interactions**
- Row click → [4] Assessment Result
- *Raise reassessment* on an expired row → [2] New Assessment prefilled with the previous
  application, branch and artifact pattern, requiring a fresh report URL and artifact
- *Fix and resubmit* on a failed row → [2] prefilled with the previous inputs
- Expiry countdown is prominent from 48 hours out; the row does not silently change state

**States**
- *Empty* — first-time user: explain what an assessment is and what they need to hand (report
  URL, artifact reference) before starting
- *Loading* — skeleton rows
- *Error* — retry affordance, no data loss

---

### [4] Assessment Result

Read-only outcome for the requester. Same data as the reviewer sees, without controls.

Per finding: CVE, component, outcome, and the reason in plain language. A Not Affected
finding must show what evidence cleared it — a requester who cannot see the reasoning cannot
learn from it, and next quarter raises the same request.

Findings marked Risk Acceptance Required carry an explicit next step: *"No fix is available.
This did not receive a determination. Take the evidence package to your risk manager."* with
a package download. This must not look like a resolved item.

**States** — *loading* skeleton; *error* retry; no empty state (an assessment always has
findings, or it would have failed admission).

---

### [5] Review Queue — the daily driver

Finding-level rows across all assessments. This is where the AppSec team spends its time.

```
┌─ Review Queue ─────────────────────────────────── 47 open ─────┐
│ [needs review ▾] [application ▾] [SLA ▾] [tier ▾]   ⌕ search   │
│ ───────────────────────────────────────────────────────────────│
│ ☐ ⚑ ASM   APPLICATION    CVE             RECOMMENDED  SLA  AGE │
│ ───────────────────────────────────────────────────────────────│
│ ☐ ▲ 2418  payments-api   CVE-2023-20860  needs review  4h   2d │
│ ☐ ▲ 2418  payments-api   CVE-2022-1471   needs review  4h   2d │
│ ☐ ✓ 2417  ledger-svc     CVE-2022-42889  not affected  ok   1d │
│ ☐ ✗ 2416  auth-gateway   CVE-2024-1597   affected      —    1d │
│ ☐ ▲ 2415  batch-runner   CVE-2021-44228  needs review  1h!  4d │
│ ☐ ⚑ 2415  batch-runner   CVE-2019-17571  risk accept.  —    4d │
│ ───────────────────────────────────────────────────────────────│
│ 3 selected      [ Accept recommendations ]  [ Send to review ] │
│                 group by: ( ) none  (•) assessment             │
└────────────────────────────────────────────────────────────────┘
```

**Columns** — selection checkbox · outcome icon · assessment ID · application · CVE ·
recommended outcome · SLA remaining · age. Sortable on every column; SLA is the default sort,
most urgent first.

**Filters** — outcome state, application, SLA band, evidence tier, free-text search across CVE
and component. Filters persist across drawer open/close and across navigation. A reviewer who
loses their filter set on every drill-in will stop using the filters.

**Grouping toggle** — flat finding rows (default, for working) or collapsed by assessment (for
tracking). Same data, same component.

**Bulk actions** — apply only to selected rows, and only where the action is legal for every
selected row. *Accept recommendations* must refuse a selection containing anything that
requires individual attention, and say which rows blocked it. Bulk approval of Tier 2
determinations must be prevented — those require an individual second confirmation.

**Interactions**
- Row click → Evidence Drawer opens on the right, row stays highlighted, queue stays scrolled
- `j` / `k` or arrow keys → move selection; the drawer follows without closing
- `a` accept · `d` mark affected · `s` skip · `Esc` close drawer
- Assessment ID click → [6] Assessment Detail

**States**
- *Empty (no filter)* — "Nothing needs review." Genuinely good news; say so plainly rather
  than showing an error-shaped empty state
- *Empty (filtered)* — distinguish from the above and offer to clear filters
- *Loading* — skeleton rows, filters remain interactive
- *Error* — banner above a stale table, with the last-updated time. Never blank the table on a
  refresh failure; a reviewer mid-session loses their place

---

### [6] Assessment Detail

Screen 5, scoped to one assessment, plus a header carrying assessment-level context.

```
┌─ ASM-2418 · payments-api ──────────────────────── NEEDS REVIEW ┐
│ report 38ef4d1f · release/1.14 @ 4a9f1c2 · submitted 2d ago    │
│ provenance ✓ 118/118 components matched · artifact :1.14.2     │
│ requester j.doe · "upgrade blocked until Q4 platform release"  │
│ ───────────────────────────────────────────────────────────────│
│  8 not affected   ·   3 need review   ·   1 risk acceptance    │
│  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░  progress                 │
│ ───────────────────────────────────────────────────────────────│
│              [ same findings table as Review Queue ]           │
│ ───────────────────────────────────────────────────────────────│
│      [ Approve all reviewed ]    [ Return to requester ]       │
└────────────────────────────────────────────────────────────────┘
```

The header exists so a reviewer never has to leave to answer "what am I looking at, and can I
trust the inputs". Provenance status belongs here, prominently — it is the basis of every
determination below it.

**Approve all reviewed** is the approver's commit action. It creates the determinations in IQ.
Separation of duties applies: if the current user is the requester, this control is absent
with an explanation, not merely disabled.

---

### ((Evidence Drawer)) — overlay

Opens over screens 5, 6 and 8. Read-only in 8.

```
                          ┌─ CVE-2023-20860 ─────────────── ✕ ─┐
                          │ spring-web 5.3.26 · threat 8       │
                          │ transitive via spring-boot-starter │
                          │ ─────────────────────────────────  │
                          │ RECOMMENDATION                     │
                          │  ▲ Under Investigation             │
                          │  the vulnerable class ships and    │
                          │  nothing references it, but the    │
                          │  app uses component scanning, so   │
                          │  absence of a reference is not     │
                          │  proof of non-use                  │
                          │ ─────────────────────────────────  │
                          │ RULE TRACE                         │
                          │  T1 class present ......... ships  │
                          │  T2 constant pool ......... 0 refs │
                          │     84 app classes scanned         │
                          │  T2 source search ......... 0 hits │
                          │  T2 escape hatch .......... FOUND  │
                          │     @ComponentScan in 3 files ▸    │
                          │ ─────────────────────────────────  │
                          │ ESCALATION SIGNALS      not a basis│
                          │  EPSS 0.021 · not KEV              │
                          │  CVSS 7.5 AV:N/AC:L/PR:N/UI:N      │
                          │  fix available: 5.3.27 ▸           │
                          │ ─────────────────────────────────  │
                          │ DETERMINATION                      │
                          │  ( ) Not Affected  ▾ justification │
                          │  ( ) Affected                      │
                          │  (•) Under Investigation           │
                          │  note [ ........................ ] │
                          │                                    │
                          │  [ Save ]      ↑ prev    next ↓    │
                          └────────────────────────────────────┘
```

**Sections, in this order**
1. *Identity* — CVE, component, version, threat level, direct or transitive
2. *Recommendation* — the proposed outcome and a plain-language reason. Never a bare enum
3. *Rule trace* — every rule that ran, its result, and what it examined. Expandable to the raw
   evidence. This is the audit surface and the reviewer's trust surface
4. *Escalation signals* — EPSS, KEV, CVSS, fix availability. **Visually separated and labelled
   as not a basis for clearing.** They explain routing, never resolution
5. *Determination controls* — the three outcomes, a justification select enabled only for Not
   Affected, and a free-text note

**Constraints the UI must enforce**
- Selecting *Not Affected* requires a justification; the justification list contains only
  those permitted at the achieved evidence tier. Perimeter and mitigating-control
  justifications never appear
- A Tier 2 determination shows that a second confirmation is required, and by whom
- Where the adjudicator abstained, show what evidence was missing. That list is how the
  collectors get improved

**States**
- *Loading* — sections stream in as collectors return; the identity block renders immediately
- *Partial* — a collector failed. Show which one and that the recommendation was made without
  it. **A failed collector must never render as a passed check** — that would manufacture
  evidence out of an outage
- *Error* — determination save failed: keep the reviewer's input, do not close the drawer

---

### [7] Dashboard — Auditor and Management

Answers: how much is flowing through, what is it deciding, is it trustworthy, is the team
keeping up.

**Panels**
1. *Volume over time* — assessments and findings, by outcome
2. *Automation split* — auto-determined vs human-reviewed, trending. The headline number for
   whether the portal is working
3. *SLA* — median and 90th percentile time to determination; count breaching
4. *Agreement rate per rule* — where the portal's recommendation matched the human decision.
   **The trust metric.** A rule dropping below its bar loses auto-determination privilege, and
   that must be visible here
5. *Outcome mix* — Not Affected / Affected / Risk Acceptance Required, by application
6. *Determination expiry* — how many lapse in the next 7 days, i.e. incoming reassessment load

Every panel is filterable by date range and application, and every number links through to the
underlying findings. An auditor who cannot get from a number to its rows will not trust it.

**States** — *empty*: pre-launch, explain that metrics appear once assessments complete;
*loading*: per-panel skeletons; *error*: per-panel, one failed panel must not blank the page.

---

### [8] Risk Acceptance Queue — Risk Manager

Findings where no fix exists. **These received no determination and the IQ violation is still
open.** The screen must be unambiguous about that.

Per row: application, CVE, component, why no fix is available, CVSS/EPSS/KEV, affected
applications count, age, and the current hand-off status (*Awaiting hand-off* / *With risk
manager* / *Accepted* / *Rejected*).

The primary action is *Download evidence package* — a self-contained document the app team
takes to their risk manager. No integration with the GRC system; this is a deliberate
hand-off, tracked only to the point of leaving the portal.

Status is manually set by the risk manager, and the screen states plainly that the portal does
not enforce the outcome.

---

### [9] Rules & Thresholds — Admin

Per rule: identifier, tier, version, whether auto-determination is enabled, current agreement
rate against its bar, and volume in the last 30 days.

**Controls**
- Enable / disable auto-determination per rule
- Set the agreement bar per rule
- Set EPSS threshold and other escalation triggers
- View version history and which determinations were made under which version

**Constraints the UI must enforce**
- A Tier 3 rule has no auto-determination toggle. Not disabled — absent, because the capability
  does not exist. Rendering a greyed-out toggle implies it could be turned on
- A rule below its agreement bar shows as auto-suspended, with the reason
- Changing a threshold shows how many of the last 30 days' findings would have been routed
  differently, before saving

---

## 3. Cross-cutting

**Responsive** — the queue and dashboard are desktop-first; this is deskbound work. Below
~1100px the Evidence Drawer becomes full-screen with a back affordance. Table columns collapse
in priority order: age, then SLA, then application. CVE and outcome never collapse.

**Keyboard** — the queue is fully keyboard operable: `j`/`k` navigate, `Enter` opens the
drawer, `a`/`d`/`s` set outcomes, `Esc` closes, `/` focuses search. This is the difference
between a tool the team uses and one they tolerate.

**Accessibility** — outcome must never be conveyed by colour alone; every state carries an icon
and a text label. The drawer traps focus while open and returns focus to the originating row on
close. Live regions announce collector completion so a screen-reader user is not left waiting
in silence.

**Loading philosophy** — the portal calls several slow upstreams. Stream results in rather than
blocking on the slowest. Never show a spinner where a partial answer is available, and never
show a partial answer as if it were complete.

---

## 4. Open questions for the design pass

1. Should the Review Queue default to finding-level or assessment-level grouping for a first-
   time reviewer?
2. Does the requester need to see the rule trace, or only the plain-language reason?
3. Should Risk Acceptance Required findings appear in the Review Queue at all, or only in
   screen 8?
