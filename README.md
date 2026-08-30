# VEX Portal

**VEX — Vulnerability Exploitability eXchange.** An open standard for recording whether a known
vulnerability actually affects a specific product. An SBOM says a component is present; VEX
says whether the vulnerability in it is exploitable in your context.

Evidence-based CVE applicability determinations over Sonatype Nexus IQ Lifecycle, recorded in
CycloneDX VEX format.

App teams raise an assessment; the portal resolves most of them deterministically from
artifact and source evidence, uses an evidence-bound AI adjudicator for a constrained
middle band, and routes only genuinely ambiguous cases to a human — with a full audit
trail behind every outcome.

## The problem this solves

A four-person AppSec team supports ~2,500 developers. Nexus IQ's reachability analysis is
not dependable enough to act on, so exploitability review happens off-pipeline: requests
arrive by Teams, email, and service requests, and are worked by hand. Nothing is tracked,
nothing is reused, and the outcome depends on who ran the review.

## Terminology

Full rationale for the name and the vocabulary: [`docs/naming.md`](docs/naming.md).

**This portal does not use the word "waiver."** Audit and management read it as suppressing
a real finding. What the portal records is a *determination* that a vulnerability does not
apply, in CycloneDX VEX vocabulary:

| Term | Meaning |
|---|---|
| **Exploitability Assessment** | A request to assess whether a CVE applies to an application |
| **Not Affected** | The vulnerability is not exploitable here |
| **Affected** | It is exploitable; remediation required |
| **Under Investigation** | Insufficient evidence; awaiting human review |
| **Reassessment** | A fresh assessment after the 7-day window |

The IQ waiver is the *enforcement mechanism* behind a Not Affected determination — an
implementation detail of the IQ adapter, never a concept surfaced in the UI or reports.

## How a determination is reached

Evidence is tiered, and the tier decides what the evidence is allowed to do:

- **Tier 1 — proof.** The vulnerable class is absent from the shipped artifact. May clear a
  finding on its own.
- **Tier 2 — strong but defeasible.** Nothing references the vulnerable class (constant-pool
  and source evidence), the required gadget component is absent, the runtime is outside the
  affected range. May clear a finding only with an independent second confirmation, and only
  when no dynamic-dispatch escape hatch is present.
- **Tier 3 — escalation only.** CVSS vector, EPSS, KEV, exposure. May raise severity or route
  to a human. **May never clear a finding.** This is enforced in code, not by reviewer
  discipline — see `backend/app/domain/determination.py`.

Determinations expire after 7 days and are not auto-renewed. All branches scan into the same
IQ application, so a determination made against one branch cannot be assumed valid for
another that may reach a vulnerable method the first does not.

No fix available is never a Not Affected determination. Those cases are marked
`RISK_ACCEPTANCE_REQUIRED`, and the app team takes the evidence package to their risk
manager. The violation stays open in IQ — accepted risk must not be made invisible.

## Stack

| Layer | Choice |
|---|---|
| Backend | Python 3.12 + FastAPI + SQLAlchemy (async) |
| Frontend | Angular |
| Database | SQLite (schema kept portable — a server DB is a connection-string change) |
| AI | Claude via AWS Bedrock (private VPC) |

Mirrors DAST-Portal so the same rotation maintains both. Versions are pinned and must not
be floated.

## Quickstart

```bash
just install     # backend venv + deps
just migrate     # creates backend/data/vex.db
just test        # run the suite
just dev-api     # http://localhost:8000
just dev-web     # http://localhost:4200
```

## Documentation

- [`docs/design.md`](docs/design.md) — full design: architecture, evidence tiers, provenance,
  RBAC, phased delivery, verification

- [`docs/design/ui-spec.md`](docs/design/ui-spec.md) — screen inventory, navigation, per-screen
  layout and states; input document for the UI design pass
- [`docs/naming.md`](docs/naming.md) — what VEX stands for, why the portal is named after it,
  and why the word "waiver" is banned from the interface
