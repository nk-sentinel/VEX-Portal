/**
 * Pure view-model helpers for [9] Rules & Thresholds. No Angular imports —
 * same pattern as `features/review/review.model.ts`.
 */

import type { EscalationRuleOut, PendingRuleOut, RuleOut, ToggleableRuleOut } from '../../core/api/models';

export { formatPercent, percentWidth } from '../dashboard/dashboard.model';
export { tierBadgeClass, tierLabel } from '../review/review.model';

/**
 * Discriminates the three shapes `GET /api/admin/rules` returns.
 * `has_auto_determination_toggle` is `true`/`false` for a registered rule,
 * and genuinely ABSENT for a pending (unregistered) one — never a boolean
 * `false` standing in for "no capability", which is exactly the distinction
 * the Tier 3 "no toggle at all" requirement rests on.
 */
export function isToggleable(rule: RuleOut): rule is ToggleableRuleOut {
  return 'has_auto_determination_toggle' in rule && rule.has_auto_determination_toggle === true;
}

export function isEscalation(rule: RuleOut): rule is EscalationRuleOut {
  return 'has_auto_determination_toggle' in rule && rule.has_auto_determination_toggle === false;
}

export function isPending(rule: RuleOut): rule is PendingRuleOut {
  return !('has_auto_determination_toggle' in rule);
}

/** Registered rules (toggleable + escalation) in one table, tier then id. */
export function registeredRules(rules: readonly RuleOut[]): (ToggleableRuleOut | EscalationRuleOut)[] {
  return rules.filter((r): r is ToggleableRuleOut | EscalationRuleOut => isToggleable(r) || isEscalation(r));
}

/** The unregistered rules — "clearly marked as having no evidence source", never mixed into the registered table. */
export function pendingRules(rules: readonly RuleOut[]): PendingRuleOut[] {
  return rules.filter(isPending);
}
