/**
 * Pure view-model helpers for [7] Dashboard. No Angular imports — same
 * pattern as `features/review/review.model.ts`.
 */

/** `null` (no data) renders "—", never a fabricated "0%". */
export function formatPercent(ratio: number | null | undefined): string {
  if (ratio == null) return '—';
  return `${Math.round(ratio * 100)}%`;
}

export function formatHours(hours: number | null | undefined): string {
  if (hours == null) return '—';
  if (hours < 1) return '<1h';
  if (hours < 48) return `${hours.toFixed(1)}h`;
  return `${(hours / 24).toFixed(1)}d`;
}

export function percentWidth(ratio: number | null | undefined): string {
  if (ratio == null) return '0%';
  return `${Math.min(100, Math.max(0, ratio * 100))}%`;
}

/** Date range presets — [7]'s "last N days" select. */
export type RangePreset = 7 | 30 | 90;

export function rangeSince(preset: RangePreset, now: Date): string {
  return new Date(now.getTime() - preset * 24 * 3_600_000).toISOString();
}

/**
 * A stacked-bar segment's width, as a percentage of `total` — used for the
 * volume-by-outcome bar and the outcome-mix-by-application bars. `total ===
 * 0` returns `0%` rather than `NaN%`.
 */
export function segmentWidth(count: number, total: number): string {
  if (total <= 0) return '0%';
  return `${(count / total) * 100}%`;
}

/**
 * `VolumePanel.findings_by_outcome` (`app/api/dashboard.py::volume`) is a
 * SPARSE map — an outcome with zero findings in the window is simply
 * absent from it, not present with a `0` value (`counts.get(key, 0) + 1`
 * only ever runs for a key that occurred at least once). The TS interface
 * types it as `Record<string, number>` for convenience, which makes a
 * direct `map['affected']` look statically always-defined — this helper is
 * the one place that (correctly) treats it as possibly missing, so the
 * template never has to fight Angular's strict-template "this `??` is
 * unreachable" diagnostic while still rendering `0`, not `undefined`, for
 * an absent key.
 */
export function countOf(map: Record<string, number> | undefined, key: string): number {
  return map?.[key] ?? 0;
}
