# Decision Engine — Phases 3 & 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Turn observed evidence into determinations. Admission checks, the tiered rule engine, the AI adjudicator, and the four outcomes — the whole decision flow, no screens.

**Architecture:** A rule engine over the `EvidencePack` the evidence layer already produces. Rules are declarative, versioned, and carry their tier. The engine is the ONLY place tier restrictions are enforced. The adjudicator handles a constrained middle band with a closed output contract and a mandatory abstain path.

**Tech Stack:** Python 3.12, existing dependencies. No new ones.

**Spec:** `docs/design.md` — "Deterministic decision tiers", "Four terminal outcomes", "AI adjudication".

## Global Constraints

- Python `>=3.12`. No new dependencies.
- **Never the word "waiver"** outside `app/adapters/iq/`.
- **Tier 3 evidence may never clear a finding.** CVSS, EPSS, KEV, exposure and app criticality may raise severity or route to a human — never justify Not Affected. Already enforced in `app/domain/determination.py::Determination.validate`; the engine must not provide a path around it.
- **A failure is never absence.** Any collector or rule that cannot answer must say so, not return a negative. An unanswerable rule makes the finding inconclusive, never clear.
- **The adjudicator must be able to abstain.** Without `insufficient_evidence` the "unsure" bucket stays silently empty and ambiguous cases get forced into confident-looking verdicts.
- **No fix available is never a determination.** It is `RISK_ACCEPTANCE_REQUIRED`, the IQ violation stays open, and the portal does not automate the hand-off.
- `ruff check app tests` and `mypy app` (strict) must pass. Line length 100.
- The existing 344 backend tests must keep passing.

---

## File Structure

| File | Responsibility |
|---|---|
| `app/rules/engine.py` | Rule registry, execution, tier enforcement, aggregation |
| `app/rules/tier1.py` | Proof rules — may clear a finding alone |
| `app/rules/tier2.py` | Strong-but-defeasible rules + the dynamic-dispatch anti-check |
| `app/rules/tier3.py` | Escalation signals — may only raise severity or route to a human |
| `app/services/admission.py` | Report/artifact/provenance checks before a case is accepted |
| `app/services/collection.py` | Orchestrates the collectors into an `EvidencePack` |
| `app/services/adjudication.py` | Evidence pack → strict verdict, refute pass, abstention |
| `app/services/determination.py` | Combines rule + AI output into one of four outcomes; commits to IQ |

---

### Task 1: Rule engine core

**Files:** Create `app/rules/engine.py`; test `tests/rules/test_engine.py`

**Produces:** `Rule` protocol (`id`, `version`, `tier`, `evaluate(pack, component) -> RuleResult`), `RuleResult` (`verdict`, `justification`, `detail`), `RuleVerdict` enum (`SATISFIED`/`NOT_SATISFIED`/`INAPPLICABLE`/`UNANSWERABLE`), `RuleEngine.evaluate_component(...) -> EngineOutcome`

The engine's job is aggregation under a safety rule, not cleverness.

- [ ] **Step 1: Write the failing tests**

```python
def test_tier3_rule_alone_can_never_clear_a_finding():
    # The load-bearing property. Escalation evidence may raise severity or
    # route to a human; it may never be the reason a vulnerability is
    # declared not applicable.
    engine = RuleEngine([AlwaysSatisfied(tier=EvidenceTier.ESCALATION)])
    outcome = engine.evaluate_component(pack, component)
    assert outcome.proposed is not FindingOutcome.NOT_AFFECTED


def test_a_tier1_rule_alone_can_clear_a_finding():
    engine = RuleEngine([AlwaysSatisfied(tier=EvidenceTier.PROOF,
                                         justification=Justification.CODE_NOT_PRESENT)])
    outcome = engine.evaluate_component(pack, component)
    assert outcome.proposed is FindingOutcome.NOT_AFFECTED
    assert outcome.tier is EvidenceTier.PROOF


def test_a_tier2_rule_alone_requires_a_second_confirmation():
    engine = RuleEngine([AlwaysSatisfied(tier=EvidenceTier.STRONG,
                                         justification=Justification.CODE_NOT_REACHABLE)])
    outcome = engine.evaluate_component(pack, component)
    assert outcome.proposed is FindingOutcome.NOT_AFFECTED
    assert outcome.requires_second_confirmation is True


def test_an_unanswerable_rule_makes_the_finding_inconclusive_never_clear():
    # A rule that could not evaluate is not evidence of anything. Treating
    # UNANSWERABLE as NOT_SATISFIED would let a broken collector clear findings.
    engine = RuleEngine([
        AlwaysSatisfied(tier=EvidenceTier.PROOF, justification=Justification.CODE_NOT_PRESENT),
        Unanswerable(tier=EvidenceTier.PROOF),
    ])
    outcome = engine.evaluate_component(pack, component)
    assert outcome.proposed is FindingOutcome.NEEDS_REVIEW


def test_a_hard_blocker_overrides_every_clearing_rule():
    # KEV, reachable-with-evidence, EPSS over threshold, CVSS >= 9 with
    # AV:N/PR:N/UI:N. No amount of Tier 1 evidence clears these automatically.
    engine = RuleEngine([AlwaysSatisfied(tier=EvidenceTier.PROOF,
                                         justification=Justification.CODE_NOT_PRESENT)])
    outcome = engine.evaluate_component(pack_with_kev, component)
    assert outcome.proposed is FindingOutcome.NEEDS_REVIEW
    assert "kev" in outcome.blocked_by


def test_every_rule_that_ran_is_recorded_even_when_it_did_not_decide():
    # The rule trace is the reviewer's trust surface and the audit record.
    outcome = RuleEngine([...]).evaluate_component(pack, component)
    assert {r.rule_id for r in outcome.results} == {"t1-class-absent", "t3-epss"}
```

- [ ] **Step 2–5:** verify failure; implement; the engine must:
  - run every registered rule, recording each result regardless of outcome
  - propose `NOT_AFFECTED` only when a rule of tier PROOF or STRONG is SATISFIED with a justification that `Justification.justifies_determination()` permits
  - set `requires_second_confirmation` when the deciding tier is STRONG
  - propose `NEEDS_REVIEW` when any rule is UNANSWERABLE, or when a hard blocker fires
  - never let a Tier 3 result influence `proposed` except toward `NEEDS_REVIEW`
  - lint, types, commit

---

### Task 2: Tier 1 rules

**Files:** Create `app/rules/tier1.py`; test `tests/rules/test_tier1.py`

Proof rules. Each may clear a finding alone.

| Rule id | Satisfied when | Justification |
|---|---|---|
| `t1-class-absent` | No implicated class is present in the artifact | `CODE_NOT_PRESENT` |
| `t1-component-absent` | The component is not in the runtime artifact at all | `CODE_NOT_PRESENT` |
| `t1-cve-withdrawn` | The vulnerability is withdrawn, disputed or superseded | — routes to a data-correction outcome, NOT a determination |

- [ ] Tests: each rule SATISFIED on its positive case, NOT_SATISFIED on its negative, and **UNANSWERABLE when the evidence it needs is missing from the pack** — not NOT_SATISFIED. A missing collector result must never read as "the class is absent".

---

### Task 3: Tier 2 rules and the anti-check

**Files:** Create `app/rules/tier2.py`; test `tests/rules/test_tier2.py`

| Rule id | Satisfied when | Justification |
|---|---|---|
| `t2-not-referenced` | Nothing in the app's bytecode references the class **and** the scan was conclusive | `CODE_NOT_REACHABLE` |
| `t2-gadget-absent` | A required companion component is absent from the classpath | `REQUIRES_DEPENDENCY` |
| `t2-runtime-immune` | The runtime version falls outside the affected range | `REQUIRES_ENVIRONMENT` |

**The anti-check is mandatory and belongs here.** `t2-not-referenced` must return NOT_SATISFIED — never SATISFIED — when `reference_scan_conclusive` is False. Reflection, `ServiceLoader`, component scanning, JNDI and SpEL all reach classes no constant pool mentions, and the evidence layer already reports that. A rule that ignores it clears findings on absent evidence.

- [ ] Tests: each rule; the anti-check gate; and a test that a Tier 2 clear always carries `requires_second_confirmation`.

---

### Task 4: Tier 3 escalation signals

**Files:** Create `app/rules/tier3.py`; test `tests/rules/test_tier3.py`

`t3-kev`, `t3-epss`, `t3-cvss-vector`, `t3-no-fix-available`.

These produce **signals, never clearances**. Two behaviours only: raise severity, or route to a human. `t3-no-fix-available` is special — it proposes `RISK_ACCEPTANCE_REQUIRED`, which is a hand-off, not a determination, and the IQ violation stays open.

- [ ] Tests: a property test asserting **no combination of Tier 3 rules, in any quantity, ever yields NOT_AFFECTED**. Generate combinations rather than listing them.

---

### Task 5: Admission service

**Files:** Create `app/services/admission.py`; test `tests/services/test_admission.py`

Three checks before a case is accepted, per `docs/design.md`:
1. The IQ report is retrievable
2. The artifact is retrievable
3. **The artifact matches the report** — the provenance fingerprint

Each failure is distinct and its message must say what the requester should do. Provenance mismatch is a hard stop, not a warning: an artifact that is not the scanned build makes every downstream conclusion describe different software.

- [ ] Tests: each check's failure path; that a mismatch blocks admission; that the failure messages differ.

---

### Task 6: Evidence collection orchestration

**Files:** Create `app/services/collection.py`; test `tests/services/test_collection.py`

Fetches the report, the vuln details per CVE, the artifact, and the source repo; builds the `EvidencePack`; snapshots the decision-relevant extract into `evidence`.

**Snapshot, do not reference.** Build-stage reports purge on a short window while determinations outlive them. A determination whose justification points into a system that garbage-collects it is not defensible.

**Filter `rootCauses[].listOfPaths` to `.class` entries** — IQ includes bare jar filenames, and a jar name handed to the presence check produces a meaningless answer.

- [ ] Tests: the pack is built from real fake-server data; the snapshot is stored; a collector failure makes the finding inconclusive rather than clear.

---

### Task 7: AI adjudicator

**Files:** Create `app/services/adjudication.py`; test `tests/services/test_adjudication.py`

Evidence pack in, strict closed output out.

- The prompt carries **evidence, not a question**. Determinism comes from constrained input and a closed output vocabulary, not from prompt wording.
- Output is validated against the `AiVerdictDto` contract. A malformed response is a failure, not a guess.
- **Abstention is a first-class outcome.** `insufficient_evidence` routes to a human.
- **A refute pass runs on any proposed clear.** A second, independent call prompted to refute; disagreement routes to a human. Auto-reject needs no refute pass — it is already the safe direction.
- The **CVE-intrinsic cache** (`cve_profile`) is consulted first. What a CVE requires is app-independent; only applicability is per-app. This is what makes the volume affordable.

- [ ] Tests: a valid verdict parses; a malformed one raises; abstention routes to review; the refute pass runs on a clear and not on a reject; disagreement routes to review; the cache is used on a second call for the same CVE.

---

### Task 8: Determination service

**Files:** Create `app/services/determination.py`; test `tests/services/test_determination.py`

Combines rule output and AI verdict into exactly one of four outcomes, persists it, and commits `NOT_AFFECTED` to IQ.

- `Determination.validate()` is called before anything is persisted or sent. It is the last gate.
- Expiry is 7 days, `expireWhenRemediationAvailable` true.
- The IQ suppression id comes from a **follow-up read**, not the create call — IQ returns `204 No Content`. If that read finds nothing, raise; a determination whose id we cannot establish can never be revoked or audited.
- `RISK_ACCEPTANCE_REQUIRED` **commits nothing to IQ** and leaves the violation open.
- Every transition writes an `audit_entry`.

- [ ] Tests: each of the four outcomes; that risk-acceptance writes nothing to IQ; that a failed `validate()` blocks persistence; that the audit entry is written; that a missing suppression id raises.

---

## Verification

- A finding with the class absent → `NOT_AFFECTED`, tier 1, IQ suppression created with a 7-day expiry
- A finding with a KEV CVE → `NEEDS_REVIEW` regardless of Tier 1 evidence
- A finding with no fix → `RISK_ACCEPTANCE_REQUIRED`, nothing sent to IQ
- A finding whose reference scan is inconclusive → never cleared by `t2-not-referenced`
- Property test: no combination of Tier 3 signals yields `NOT_AFFECTED`
- The 344 existing tests still pass
