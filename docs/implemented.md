# What is implemented

Snapshot 2026-10-19 — branch `feat/evidence-foundation`, 606 backend tests, 346 Karma
specs, ruff + mypy strict clean. Running at `vex.shadow-lab.org` against four fake vendors.

## Features

**Intake and admission**
- Raise an assessment: typed application id, report id (URL parsed client-side), JFrog
  artifact coordinates, optional commit sha, mandatory requester note
- Three admission checks, each a hard stop with an actionable message: report retrievable,
  artifact retrievable and readable, **provenance fingerprint** (artifact hashes vs the
  report's component hashes). Unproven provenance is refused like a confirmed mismatch
- Container images supported: pull, walk layers, recover the inner app archive

**Evidence collection** (all offline, standard library only)
- Archive inventory for JAR/WAR/EAR, including nested libraries and `META-INF/versions/N/`
- Class-presence resolution for the CVE's implicated paths
- Constant-pool reference scan of the application's own bytecode
- Escape-hatch detection (reflection, `ServiceLoader`, SpEL, JNDI...) which marks a
  reference scan inconclusive
- IQ vuln lookup per CVE: CVSS, EPSS, tri-state KEV, `rootCauses`
- IQ remediation per component: fix availability, direct vs transitive
- Bitbucket symbol search — stored as reviewer context, read by no rule
- Evidence rows snapshot the decision-relevant extract, never a pointer into a system that purges

**Decision engine**
- 7 active rules: Tier 1 `ClassAbsent`, `ComponentAbsent`; Tier 2 `NotReferenced`;
  Tier 3 `Kev`, `Epss`, `CvssVector`, `NoFixAvailable`
- 3 written, tested, deliberately unregistered — no evidence source exists
  (`rules/registry.py::PENDING_EVIDENCE`)
- Hard blockers: KEV, reachable-with-call-path, EPSS over threshold, CVSS ≥ 9 with
  `AV:N/PR:N/UI:N`. Read directly off the signals, independent of rule registration
- Tier-3-never-clears enforced in three independent places: `Determination.validate`,
  the rule engine's aggregation, and the determination service
- `UNANSWERABLE` from any rule routes the whole finding to review
- AI adjudicator over Bedrock: closed enum output, abstention path, refute pass on every
  Tier 2 clear, prompt deliberately blind to CVSS/EPSS/KEV
- Four terminal outcomes: `NOT_AFFECTED`, `AFFECTED`, `NEEDS_REVIEW`,
  `RISK_ACCEPTANCE_REQUIRED`
- 7-day determination, committed to IQ as a policy waiver with a structured reason and the
  assessment id in the comment; suppression id resolved by follow-up read

**Review and audit**
- Review queue with filters, finding detail, evidence drawer with the full rule trace
- Reviewer recommends; approver commits. Separation of duties enforced (requester ≠ approver)
- An approver cannot commit `not_affected` without PROOF/STRONG evidence on the trace
- Append-only audit entry on every transition
- Risk-acceptance queue with hand-off status and evidence-package download
- Dashboard: volume, automation split, SLA, agreement, outcome mix, expiry
- Rules admin: per-rule auto-determination toggle, thresholds; Tier 3 rules render no toggle

**Platform**
- 10 tables: `user`, `assessment`, `finding`, `evidence`, `cve_profile`, `rule_result`,
  `ai_verdict`, `iq_determination_link`, `audit_entry`, `rule_config`
- SQLite, portable schema, 3 Alembic migrations
- Adapters for IQ, JFrog, Bitbucket, Bedrock (each with a fake) and ELK (no fake, unwired)
- `/health` reports status, adapter mode and version — nothing else
- Nine screens, Angular, zero npm deps beyond Angular itself
- Traefik split by path behind the Cloudflare tunnel

## RBAC

Six roles, eight capabilities. Call sites check a **capability**, never a role, so a
permission change is a one-line mapping edit (`app/services/authorization.py`).

| Capability | requester | reviewer | approver | auditor | risk_manager | admin |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| `raise_assessment` | ● | | | | | |
| `view_queue` | | ● | ● | ● | | |
| `recommend_determination` | | ● | ● | | | |
| `commit_determination` | | | ● | | | |
| `view_dashboard` | | | | ● | | ● |
| `view_risk_acceptance` | | | | ● | ● | |
| `manage_risk_acceptance` | | | | | ● | |
| `manage_rules` | | | | | | ● |

Notes:
- An auditor can **see** the risk-acceptance queue but not change its status — read-only by
  definition, so the write is a separate capability
- `commit_determination` is approver-only, and additionally blocked when the actor raised
  the assessment (`SeparationOfDutiesError` → 403)
- A test iterates `Role` and asserts every member has an LDAP group setting, so a role added
  without a mapping fails the suite rather than becoming silently unreachable
- Authentication: local provider (argon2, dummy-hash compare to avoid a username oracle) or
  LDAP with a configurable bind-DN template. `LdapUnavailable` → 503, distinct from a
  rejected credential → 401
- Application-level entitlement is **no longer checked** — see
  `docs/decisions/intake-entitlement.md`
