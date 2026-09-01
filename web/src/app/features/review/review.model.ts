/**
 * Pure view-model helpers for the Review Queue / Assessment Detail table and
 * the Evidence Drawer (screens 5, 6 — `docs/design/ui-spec.md`: "one
 * component, differently scoped" — and the drawer overlay). No Angular
 * imports here on purpose: every function is a plain, independently
 * testable mapping from the typed API shapes (`core/api/models.ts`) onto
 * the CSS classes/labels `docs/design/ui-mockups.html`'s lifted stylesheet
 * (`core/design/outcome.scss`, `data-table.scss`, `evidence-drawer.scss`)
 * expects.
 */

import type {
  EvidenceTier,
  FindingOutcome,
  Justification,
  ReviewFindingRow,
  RuleTraceEntry,
  SlaBand,
} from '../../core/api/models';

// ---------------------------------------------------------------------------
// Outcome / tier / SLA / age presentation
// ---------------------------------------------------------------------------

export interface OutcomeMeta {
  readonly label: string;
  readonly shortLabel: string;
  readonly icon: string;
  readonly cls: string;
}

/**
 * Icon + label + CSS class per `FindingOutcome`, matching
 * `docs/design/ui-mockups.html`'s `OUT`/`SHORT` maps and
 * `docs/design/ui-spec.md`'s "Finding outcomes" table exactly (glyphs
 * included — colour is never the only carrier of meaning, so every one of
 * these pairs an icon with a text label).
 *
 * `risk_acceptance_required` deliberately reuses `.outcome--handoff` — the
 * one outcome pill that is NOT filled (`tokens.scss`'s header: "It borrows
 * nothing from the green of a cleared finding").
 */
export const OUTCOME_META: Readonly<Record<FindingOutcome, OutcomeMeta>> = {
  not_affected: { label: 'Not Affected', shortLabel: 'not affected', icon: '✓', cls: 'outcome outcome--clear' },
  affected: { label: 'Affected', shortLabel: 'affected', icon: '✗', cls: 'outcome outcome--affected' },
  needs_review: { label: 'Needs Review', shortLabel: 'needs review', icon: '▲', cls: 'outcome outcome--review' },
  risk_acceptance_required: {
    label: 'Risk Acceptance Required',
    shortLabel: 'risk acceptance',
    icon: '⚑',
    cls: 'outcome outcome--handoff',
  },
};

/** `null` when the finding has no tier (never decided at PROOF/STRONG) — render no badge, not an empty one. */
export function tierBadgeClass(tier: EvidenceTier | null | undefined): string | null {
  return tier ? `tier-badge tier--${tier}` : null;
}

export function tierLabel(tier: EvidenceTier | null | undefined): string {
  return tier ? `Tier ${tier}` : '';
}

/** `sla_hours_remaining`/`age_hours` -> `"2d"` / `"4h"` / `"<1h"`, matching the mockup's compact column width. */
export function formatHoursShort(hours: number): string {
  const abs = Math.abs(hours);
  if (abs >= 24) return `${Math.floor(abs / 24)}d`;
  if (abs < 1) return '<1h';
  return `${Math.round(abs)}h`;
}

export function formatAge(ageHours: number): string {
  return formatHoursShort(ageHours);
}

/** CSS class for the SLA cell — breaching/urgent get their own token, `ok`/`n/a` stay plain. */
export function slaClass(band: SlaBand): string {
  if (band === 'breaching') return 'sla sla--breach';
  if (band === 'urgent') return 'sla sla--soon';
  return 'sla';
}

/** `—` for a decided/n-a row (nothing is "remaining"); a breaching band gets the mockup's `!` suffix. */
export function formatSla(band: SlaBand, hoursRemaining: number | null): string {
  if (band === 'n/a' || hoursRemaining == null) return '—';
  const text = formatHoursShort(hoursRemaining);
  return band === 'breaching' ? `${text} !` : text;
}

// ---------------------------------------------------------------------------
// Justification options — "only those permitted at the achieved evidence
// tier. Perimeter and mitigating-control justifications never appear."
// ---------------------------------------------------------------------------

export const JUSTIFICATION_LABELS: Readonly<Record<Justification, string>> = {
  code_not_present: 'Code not present',
  code_not_reachable: 'Code not reachable',
  requires_dependency: 'Requires an absent dependency',
  requires_configuration: 'Requires absent configuration',
  requires_environment: 'Requires a different runtime environment',
  protected_at_perimeter: 'Protected at perimeter',
  protected_by_mitigating_control: 'Protected by mitigating control',
};

/**
 * Which evidence tier's rules actually produce each justification —
 * mirrors `backend/app/domain/determination.py`'s `Justification` member
 * docstrings field-for-field. `protected_at_perimeter`/
 * `protected_by_mitigating_control` are Tier 3 (ESCALATION) — CLAUDE.md
 * rule 2 forbids Tier 3 evidence from ever clearing a finding, so these
 * never appear in {@link justificationOptionsForTier}'s output regardless
 * of the achieved tier passed in.
 */
export const JUSTIFICATION_TIER: Readonly<Record<Justification, EvidenceTier>> = {
  code_not_present: 1,
  code_not_reachable: 2,
  requires_dependency: 2,
  requires_configuration: 2,
  requires_environment: 2,
  protected_at_perimeter: 3,
  protected_by_mitigating_control: 3,
};

/**
 * The justification select's option list for a finding whose best achieved
 * evidence is `achievedTier` (`ReviewFindingDetail.recommendation.tier` —
 * server-derived, never asserted by this client). `null`/`undefined` (no
 * PROOF/STRONG evidence exists at all) returns an empty list: there is
 * nothing to justify a clear with, so the UI should disable the Not
 * Affected option entirely rather than offer a select with no
 * legal choice.
 *
 * **This is a courtesy filter, not the enforcement point.** The server's
 * `Determination.validate()` only checks `tier.may_justify()` (Tier 1/2,
 * either) and `justification.justifies_determination()` (excludes the two
 * Tier-3-only values) — it does not itself cross-check that the specific
 * justification matches the specific rule that fired. Restricting the
 * *exact* match here (rather than "any tier <= achieved", which the mockup's
 * own illustrative JS state machine uses) is this client's own, stricter
 * reading of "only those permitted at the achieved evidence tier": Tier 1
 * evidence (class absence) can only ever support `code_not_present`, never
 * one of the Tier 2 reachability-based claims, and vice versa.
 */
export function justificationOptionsForTier(achievedTier: EvidenceTier | null | undefined): Justification[] {
  // Tier 3 is excluded outright, even when `achievedTier` is somehow 3 (it
  // never legitimately is — `recommendation.tier` only ever reflects a
  // PROOF/STRONG clear — but this function fails closed rather than
  // trusting that): CLAUDE.md rule 2, "Tier 3 evidence may never clear a
  // finding."
  if (achievedTier == null || achievedTier === 3) return [];
  return (Object.keys(JUSTIFICATION_TIER) as Justification[]).filter(
    (justification) => JUSTIFICATION_TIER[justification] === achievedTier,
  );
}

// ---------------------------------------------------------------------------
// Sorting / grouping — server always returns SLA-ascending
// (`app/api/review.py`'s `list_findings`); everything else is a client-side
// re-sort over that same page, never a second network round trip.
// ---------------------------------------------------------------------------

export type SortColumn = 'assessment' | 'application' | 'cve' | 'component' | 'recommended' | 'sla' | 'age';
export type SortDirection = 'asc' | 'desc';

function slaSortKey(row: ReviewFindingRow): number {
  // `n/a`/null sorts last regardless of direction — mirrors the server's
  // own "sla_hours_remaining is None" tiebreak in `list_findings`.
  return row.sla_hours_remaining ?? Number.POSITIVE_INFINITY;
}

const SORT_KEY: Record<SortColumn, (row: ReviewFindingRow) => string | number> = {
  assessment: (row) => row.assessment_id,
  application: (row) => row.application_id,
  cve: (row) => row.cve,
  component: (row) => row.purl,
  recommended: (row) => row.recommended_outcome,
  sla: slaSortKey,
  age: (row) => row.age_hours,
};

export function sortRows(rows: readonly ReviewFindingRow[], column: SortColumn, direction: SortDirection): ReviewFindingRow[] {
  const key = SORT_KEY[column];
  const sign = direction === 'asc' ? 1 : -1;
  return [...rows].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    if (ka < kb) return -1 * sign;
    if (ka > kb) return 1 * sign;
    return a.cve.localeCompare(b.cve);
  });
}

export interface FindingGroup {
  readonly assessmentId: string;
  readonly applicationId: string;
  readonly rows: ReviewFindingRow[];
}

/**
 * Partitions an already-sorted row list by assessment, preserving each
 * group's first-seen order — "collapsed by assessment (for tracking). Same
 * data, same component." Never re-sorts within or across groups.
 */
export function groupByAssessment(rows: readonly ReviewFindingRow[]): FindingGroup[] {
  const order: string[] = [];
  const byAssessment = new Map<string, ReviewFindingRow[]>();
  for (const row of rows) {
    let bucket = byAssessment.get(row.assessment_id);
    if (!bucket) {
      bucket = [];
      byAssessment.set(row.assessment_id, bucket);
      order.push(row.assessment_id);
    }
    bucket.push(row);
  }
  return order.map((assessmentId) => {
    const bucket = byAssessment.get(assessmentId)!;
    return { assessmentId, applicationId: bucket[0].application_id, rows: bucket };
  });
}

// ---------------------------------------------------------------------------
// Bulk-action eligibility — "apply only where legal for every selected row,
// and a refusal names which rows blocked it." Bulk approval of a Tier 2
// clear must be prevented; those need an individual second confirmation.
// ---------------------------------------------------------------------------

export interface BulkBlock {
  readonly cve: string;
  readonly assessmentId: string;
  readonly reason: string;
}

/**
 * Why `row` cannot be part of a bulk "accept" action, or `null` if it is
 * legal. Every reason names the row's CVE, per ui-spec's "say which rows
 * blocked it".
 */
export function bulkBlockReason(row: ReviewFindingRow): string | null {
  if (row.outcome === 'risk_acceptance_required') {
    return 'Risk Acceptance Required — this left the portal, there is no recommendation to accept';
  }
  if (row.outcome === 'needs_review') {
    return 'routed to a human reviewer — no safe bulk recommendation exists for this finding';
  }
  if (row.tier === 2) {
    return 'Tier 2 determination — needs an individual second confirmation, never a bulk approval';
  }
  return null;
}

export function bulkBlocks(rows: readonly ReviewFindingRow[]): BulkBlock[] {
  const blocks: BulkBlock[] = [];
  for (const row of rows) {
    const reason = bulkBlockReason(row);
    if (reason) blocks.push({ cve: row.cve, assessmentId: row.assessment_id, reason });
  }
  return blocks;
}

// ---------------------------------------------------------------------------
// Rule trace — degraded-collector detection.
//
// **No data source today.** `backend/app/services/collection.py` builds a
// `CollectionFailure` per per-CVE collector error (`EvidencePack.failures`)
// but nothing downstream of that module ever reads `.failures` — confirmed
// by `grep -rn "\.failures\b" backend/app` returning nothing outside that
// one module. No `RuleResult.detail_json` a live pipeline run writes today
// carries a "this collector failed" signal distinct from a genuine
// UNANSWERABLE (evidence legitimately absent) — flagged in the task report
// as a "no data source" gap, the same category as Task 2's SSO button.
//
// This function/the drawer's rendering path exist so the distinction the
// brief requires ("a failed collector and an abstention must look nothing
// alike") is built and tested against a documented, forward-looking
// contract: a rule-trace entry is "degraded" when its `detail` carries
// `collector_status: "failed"`. Until the backend gap above is closed, no
// live rule ever sets this, and the UI path is exercised only by seeded/
// synthetic data (see the task report).
// ---------------------------------------------------------------------------

export function isDegraded(entry: RuleTraceEntry): boolean {
  return entry.detail?.['collector_status'] === 'failed';
}

export function degradedReason(entry: RuleTraceEntry): string {
  const raw = entry.detail?.['collector_error'];
  return typeof raw === 'string' && raw.length > 0
    ? raw
    : `The ${entry.rule_id} collector did not respond. The recommendation was made without it.`;
}
