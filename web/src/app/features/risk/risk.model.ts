/**
 * Pure view-model helpers for [8] Risk Acceptance Queue. No Angular
 * imports — same pattern as `features/review/review.model.ts`.
 */

import type { HandoffStatus } from '../../core/api/models';

export interface HandoffMeta {
  readonly label: string;
  readonly icon: string;
  readonly color: string;
}

/**
 * Icon + label + colour per hand-off status. Every one of these is a
 * manual, unenforced record ("the screen states plainly that the portal
 * does not enforce the outcome" — ui-spec) — never styled as a
 * determination outcome pill (`.outcome--*`), which is why this uses its
 * own small text+icon treatment rather than reusing `review.model.ts`'s
 * `OUTCOME_META`.
 */
export const HANDOFF_META: Readonly<Record<HandoffStatus, HandoffMeta>> = {
  awaiting_hand_off: { label: 'Awaiting hand-off', icon: '○', color: 'var(--fg-muted)' },
  with_risk_manager: { label: 'With risk manager', icon: '◐', color: 'var(--sev-low)' },
  accepted: { label: 'Accepted', icon: '●', color: 'var(--success)' },
  rejected: { label: 'Rejected', icon: '✕', color: 'var(--danger)' },
};

export const HANDOFF_ORDER: readonly HandoffStatus[] = [
  'awaiting_hand_off',
  'with_risk_manager',
  'accepted',
  'rejected',
];
