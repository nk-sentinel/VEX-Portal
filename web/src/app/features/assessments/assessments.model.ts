/**
 * Pure view-model helpers for screens [2] New Assessment, [3] My Assessments
 * and [4] Assessment Result. No Angular imports — same pattern as
 * `features/review/review.model.ts`, which this module imports outcome/tier
 * presentation from rather than duplicating it (one place owns "what does an
 * outcome pill look like").
 */

import type { AdmissionCheckKind, AssessmentState } from '../../core/api/models';

export {
  OUTCOME_META,
  formatAge,
  tierBadgeClass,
  tierLabel,
  JUSTIFICATION_LABELS,
} from '../review/review.model';

// ---------------------------------------------------------------------------
// Assessment-state presentation — reuses outcome.scss's `.state-pill
// state--X` classes verbatim (`X` = the wire value upper-cased), the same
// convention `features/review/review-queue.html` already uses for screen 6's
// header pill.
// ---------------------------------------------------------------------------

export function stateBadgeClass(state: AssessmentState): string {
  return `state-pill state--${state.toUpperCase()}`;
}

export function stateLabel(state: AssessmentState): string {
  return state.replace(/_/g, ' ');
}

// ---------------------------------------------------------------------------
// Expiry — "prominent from 48 hours out... the row does not silently change
// state" (ui-spec screen 3). Three bands, each with its own token
// (`tokens.scss`'s `--expiry-*`): normal, within 48 hours, lapsed.
// ---------------------------------------------------------------------------

export type ExpiryBand = 'ok' | 'near' | 'lapsed';

const NEAR_THRESHOLD_HOURS = 48;

export function expiryBand(expiresAt: string | null, now: Date): ExpiryBand {
  if (!expiresAt) return 'ok';
  const hoursRemaining = (new Date(expiresAt).getTime() - now.getTime()) / 3_600_000;
  if (hoursRemaining <= 0) return 'lapsed';
  if (hoursRemaining <= NEAR_THRESHOLD_HOURS) return 'near';
  return 'ok';
}

/** `''` for the `ok` band — plain text, no badge treatment, matching `outcome.scss`'s `.expiry` (unadorned) vs `.expiry--near`/`.expiry--lapsed`. */
export function expiryClass(band: ExpiryBand): string {
  if (band === 'near') return 'expiry expiry--near';
  if (band === 'lapsed') return 'expiry expiry--lapsed';
  return 'expiry';
}

function formatDuration(hours: number): string {
  const abs = Math.abs(hours);
  if (abs >= 24) return `${Math.floor(abs / 24)}d`;
  if (abs < 1) return `${Math.max(1, Math.round(abs * 60))}m`;
  return `${Math.round(abs)}h`;
}

/** "expires in 6d" / "expires in 47h" / "determination lapsed 2d ago". */
export function expiryLabel(expiresAt: string | null, now: Date): string {
  if (!expiresAt) return '';
  const hours = (new Date(expiresAt).getTime() - now.getTime()) / 3_600_000;
  if (hours <= 0) return `determination lapsed ${formatDuration(hours)} ago`;
  return `expires in ${formatDuration(hours)}`;
}

/** Row age ("2m ago" / "1d ago") for [3] My Assessments — relative to `created_at`/`submitted_at`. */
export function formatRelativeAge(iso: string, now: Date): string {
  const hours = (now.getTime() - new Date(iso).getTime()) / 3_600_000;
  return `${formatDuration(hours)} ago`;
}

// ---------------------------------------------------------------------------
// Admission checks — [2]'s three named checks, each reporting independently.
// ---------------------------------------------------------------------------

export const ADMISSION_CHECK_LABEL: Readonly<Record<AdmissionCheckKind, string>> = {
  report: 'Report retrievable',
  artifact: 'Artifact retrievable',
  provenance: 'Artifact matches report',
};

/**
 * Checks are run server-side IN ORDER (report, then artifact, then
 * provenance — `backend/app/services/admission.py::admit`) and stop at the
 * first failure, so a failure at index `i` implies every check before it
 * passed (there is no way the server would have reached check `i` otherwise)
 * — this is the only "independent per-check status" signal the single
 * synchronous `POST /api/assessments` response can support; see this
 * feature's `new-assessment.ts` docstring for the full reasoning (no
 * separate per-field check endpoint exists to poll while typing).
 */
export function checkOrder(check: AdmissionCheckKind): number {
  return { report: 0, artifact: 1, provenance: 2 }[check];
}

/**
 * Extracts a bare Nexus IQ report id from either a bare id or a full report
 * URL (`https://iq.../applicationReport/<app>/<id>`, matching the mockup —
 * `RaiseAssessmentRequest.report_id` wants the bare id, there is no
 * URL-resolving endpoint). A courtesy only: an id that happens to contain no
 * `/` passes through unchanged.
 */
export function extractReportId(input: string): string {
  const trimmed = input.trim();
  const withoutHash = trimmed.split('#').pop() ?? trimmed;
  const segments = withoutHash.split('/').filter((segment) => segment.length > 0);
  return segments.length > 0 ? segments[segments.length - 1] : trimmed;
}
