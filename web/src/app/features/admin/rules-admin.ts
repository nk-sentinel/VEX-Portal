import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { firstValueFrom } from 'rxjs';

import { AdminApiService } from '../../core/api';
import type { RuleOut, ToggleableRuleOut } from '../../core/api/models';
import { formatPercent, isToggleable, pendingRules, percentWidth, registeredRules, tierBadgeClass, tierLabel } from './admin.model';

type PageState = 'loading' | 'error' | 'empty' | 'normal';

const EPSS_RULE_ID = 't3-epss';
/** `app/api/admin.py`'s own `_DEFAULT_EPSS_HARD_BLOCK` — used only to seed the input before any threshold has ever been set. */
const DEFAULT_EPSS_THRESHOLD = 0.1;

/**
 * [9] Rules & Thresholds — Admin.
 *
 * **A Tier 3 rule renders NO toggle at all.** `registeredRules()` +
 * `isToggleable()`/`isEscalation()` (`admin.model.ts`) discriminate on
 * `has_auto_determination_toggle`'s presence and value, never on whether
 * `auto_determination_enabled` happens to be falsy — the template's
 * `@if (isToggleable(rule))` branch is the only place a toggle button is
 * ever emitted, so an Escalation rule's cell renders the "no
 * auto-determination capability" note instead, structurally, not via a
 * `disabled` attribute.
 *
 * **The three unregistered rules are their own, clearly-labelled section.**
 * `pendingRules()` never merges into the registered table — a `PendingRuleOut`
 * has no tier/version/agreement/volume to show there anyway (see
 * `core/api/models.ts`'s shape), and showing seven rows where ten rules
 * exist would let an admin conclude three are broken rather than
 * deliberately parked (`app/rules/registry.py`'s own docstring, quoted here
 * because it is exactly right).
 *
 * **The EPSS threshold's "blast radius" cannot genuinely be shown BEFORE
 * saving — flagged in the task report as a real backend gap, not
 * silently reconciled.** `routing_difference_count` (how many of the last
 * 30 days' findings would route differently) is computed by
 * `PUT /api/admin/rules/{id}` ONLY as a side effect of the same call that
 * PERSISTS the new threshold (`app/api/admin.py::update_rule`) — there is
 * no dry-run/preview endpoint, and calling PUT speculatively to "preview"
 * would write a real `RuleConfig` change and a real `AuditEntry` an admin
 * never asked to commit, which corrupts the audit trail this portal exists
 * to keep trustworthy. This component does not fake a client-side
 * preview (the per-finding EPSS values `_epss_routing_difference` needs
 * are not exposed by any GET endpoint either, so one is not even
 * computable here). Instead: the impact is shown immediately AFTER Save,
 * in past tense, and a permanent, un-dismissable disclosure above the
 * control says plainly why — visible in the running product, not only in
 * this docstring, the same choice Task 3 made for "Return to requester".
 */
@Component({
  selector: 'app-rules-admin',
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './rules-admin.html',
})
export class RulesAdmin {
  private readonly api = inject(AdminApiService);

  protected readonly pageState = signal<PageState>('loading');
  protected readonly loadErrorMessage = signal<string | null>(null);
  protected readonly rules = signal<RuleOut[]>([]);

  protected readonly togglingId = signal<string | null>(null);
  protected readonly barDrafts = signal<Record<string, string>>({});
  protected readonly barSavingId = signal<string | null>(null);
  protected readonly rowError = signal<Record<string, string>>({});

  protected readonly epssDraft = signal<string>(String(DEFAULT_EPSS_THRESHOLD));
  protected readonly epssSaving = signal(false);
  protected readonly epssError = signal<string | null>(null);
  protected readonly epssResult = signal<number | null>(null);

  protected readonly registered = computed(() => registeredRules(this.rules()));
  protected readonly pending = computed(() => pendingRules(this.rules()));
  protected readonly epssRule = computed(() => this.registered().find((r) => r.rule_id === EPSS_RULE_ID) ?? null);
  protected readonly currentEpssThreshold = computed(() => {
    const thresholds = this.epssRule()?.thresholds;
    return thresholds?.['hard_block_threshold'] ?? DEFAULT_EPSS_THRESHOLD;
  });
  protected readonly epssDirty = computed(() => Number(this.epssDraft()) !== this.currentEpssThreshold());
  protected readonly epssCanSave = computed(
    () => this.epssDirty() && !this.epssSaving() && this.epssDraft().trim() !== '' && !Number.isNaN(Number(this.epssDraft())),
  );

  protected readonly EPSS_RULE_ID = EPSS_RULE_ID;
  protected readonly isToggleable = isToggleable;
  protected readonly tierBadgeClass = tierBadgeClass;
  protected readonly tierLabel = tierLabel;
  protected readonly formatPercent = formatPercent;
  protected readonly percentWidth = percentWidth;

  constructor() {
    void this.load();
  }

  private async load(): Promise<void> {
    this.pageState.set('loading');
    try {
      const rules = await firstValueFrom(this.api.listRules());
      this.rules.set(rules);
      const bars: Record<string, string> = {};
      for (const rule of registeredRules(rules)) {
        if (isToggleable(rule) && rule.agreement_bar != null) bars[rule.rule_id] = String(rule.agreement_bar);
      }
      this.barDrafts.set(bars);
      this.epssDraft.set(String(this.currentEpssThresholdFrom(rules)));
      this.pageState.set(rules.length === 0 ? 'empty' : 'normal');
    } catch (error) {
      this.loadErrorMessage.set(RulesAdmin.messageFor(error));
      this.pageState.set('error');
    }
  }

  private currentEpssThresholdFrom(rules: RuleOut[]): number {
    const rule = registeredRules(rules).find((r) => r.rule_id === EPSS_RULE_ID);
    return rule?.thresholds?.['hard_block_threshold'] ?? DEFAULT_EPSS_THRESHOLD;
  }

  protected retry(): void {
    void this.load();
  }

  protected async toggleAuto(rule: ToggleableRuleOut): Promise<void> {
    this.togglingId.set(rule.rule_id);
    this.clearRowError(rule.rule_id);
    try {
      await firstValueFrom(this.api.updateRule(rule.rule_id, { auto_determination_enabled: !rule.auto_determination_enabled }));
      await this.load();
    } catch (error) {
      this.setRowError(rule.rule_id, RulesAdmin.messageFor(error));
    } finally {
      this.togglingId.set(null);
    }
  }

  /** `barDrafts()[ruleId]` typed loosely enough that Angular's strict-template checker does not flag the `?? ''` fallback as unreachable — the map is genuinely sparse (see `dashboard.model.ts`'s `countOf` for the same shape of fix). */
  protected barDraft(ruleId: string): string {
    return this.barDrafts()[ruleId] ?? '';
  }

  protected setBarDraft(ruleId: string, value: string): void {
    this.barDrafts.update((drafts) => ({ ...drafts, [ruleId]: value }));
  }

  protected barDirty(rule: ToggleableRuleOut): boolean {
    const draft = this.barDrafts()[rule.rule_id];
    if (draft === undefined) return false;
    const draftNum = draft.trim() === '' ? null : Number(draft);
    return draftNum !== rule.agreement_bar;
  }

  protected async saveBar(rule: ToggleableRuleOut): Promise<void> {
    const draft = this.barDrafts()[rule.rule_id];
    if (draft === undefined) return;
    const value = draft.trim() === '' ? null : Number(draft);
    if (value != null && Number.isNaN(value)) return;
    this.barSavingId.set(rule.rule_id);
    this.clearRowError(rule.rule_id);
    try {
      await firstValueFrom(this.api.updateRule(rule.rule_id, { agreement_bar: value }));
      await this.load();
    } catch (error) {
      this.setRowError(rule.rule_id, RulesAdmin.messageFor(error));
    } finally {
      this.barSavingId.set(null);
    }
  }

  protected async saveEpssThreshold(): Promise<void> {
    if (!this.epssCanSave()) return;
    this.epssSaving.set(true);
    this.epssError.set(null);
    this.epssResult.set(null);
    try {
      const result = await firstValueFrom(this.api.updateRule(EPSS_RULE_ID, { epss_hard_block_threshold: Number(this.epssDraft()) }));
      this.epssResult.set(result.routing_difference_count);
      await this.load();
    } catch (error) {
      this.epssError.set(RulesAdmin.messageFor(error));
    } finally {
      this.epssSaving.set(false);
    }
  }

  protected resetEpssDraft(): void {
    this.epssDraft.set(String(this.currentEpssThreshold()));
    this.epssResult.set(null);
    this.epssError.set(null);
  }

  private setRowError(ruleId: string, message: string): void {
    this.rowError.update((errors) => ({ ...errors, [ruleId]: message }));
  }
  private clearRowError(ruleId: string): void {
    this.rowError.update((errors) => {
      const { [ruleId]: _removed, ...rest } = errors;
      return rest;
    });
  }

  private static messageFor(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (typeof error.error?.detail === 'string') return error.error.detail;
      if (error.status === 0) return 'The portal is unreachable.';
    }
    return 'That did not save. Try again.';
  }
}
