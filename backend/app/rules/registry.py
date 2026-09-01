"""The default rule registry: which rules actually run.

**Why this module exists (fix round 1, Tasks 2/3/4).** Three rule IDs the
Task 2/3 briefs specified — ``t1-cve-withdrawn``, ``t2-gadget-absent``,
``t2-runtime-immune`` — have no evidence source anywhere in this system as
built: nothing reachable from ``Rule.evaluate``'s parameters
(``EvidencePack``, ``ComponentEvidence``, ``Tier3Signals``) can answer what
they ask. Each is implemented, honestly, as always ``UNANSWERABLE``. That is
correct rule-by-rule — but ``RuleEngine.evaluate_component`` forces *the
whole finding* to ``NEEDS_REVIEW`` the moment any registered rule reports
UNANSWERABLE (see ``app/rules/engine.py``'s module docstring, priority order
point 2), regardless of what else fired. Registering an always-UNANSWERABLE
rule therefore does not make that one rule inert — it poisons every finding
processed against the registry, including ones a clean Tier 1 proof already
resolved, which defeats the tier it belongs to.

The fix is not to weaken that priority rule — it is exactly what stops a
broken collector from silently clearing a live vulnerability, and it stays
as-is. The fix is to keep these rules out of the DEFAULT registry until
their evidence exists, while keeping the rule classes and their tests: the
day the evidence arrives (a data-model addition to ``ComponentEvidence`` or
``Tier3Signals``, or a different data source — see each entry in
``PENDING_EVIDENCE`` below), they are ready to wire in.
"""

from __future__ import annotations

from app.rules.engine import Rule
from app.rules.tier1 import ClassAbsent, ComponentAbsent
from app.rules.tier2 import NotReferenced
from app.rules.tier3 import CvssVector, Epss, Kev, NoFixAvailable

#: Rules wired to a working evidence source. These run in a default
#: RuleEngine registry. Order matches the tier tables in the Task 2/3/4
#: briefs (Tier 1, then Tier 2, then Tier 3) — RuleEngine records results in
#: registration order, so this order is also the audit trace's order.
ACTIVE_RULES: tuple[Rule, ...] = (
    ClassAbsent(),
    ComponentAbsent(),
    NotReferenced(),
    Kev(),
    Epss(),
    CvssVector(),
    NoFixAvailable(),
)

#: Rules whose evidence source does not exist yet. They are written, tested,
#: and deliberately NOT registered: each can only ever return UNANSWERABLE
#: today, and one UNANSWERABLE rule forces every finding to human review,
#: which would defeat the tier it belongs to. Each entry names what it needs.
PENDING_EVIDENCE: dict[str, str] = {
    "t1-cve-withdrawn": (
        "CVE lifecycle status (withdrawn/disputed/superseded) — available from "
        "IQ's vulnerability lookup but not yet carried on VulnDetail or Tier3Signals"
    ),
    "t2-gadget-absent": (
        "which companion component a given CVE requires — this is CVE-intrinsic "
        "knowledge, so it belongs in the cve_profile cache the adjudicator builds "
        "(Task 7), not in a deterministic rule"
    ),
    "t2-runtime-immune": (
        "the artifact's runtime version (MANIFEST Build-Jdk or equivalent) against "
        "the affected range — the range is on VulnDetail already; the runtime "
        "version is not collected"
    ),
}
