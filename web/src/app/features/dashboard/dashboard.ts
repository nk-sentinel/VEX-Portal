import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { firstValueFrom, type Observable } from 'rxjs';

import { DashboardApiService } from '../../core/api';
import type {
  AgreementPanel,
  AutomationSplitPanel,
  DashboardRangeQuery,
  EvidenceTier,
  ExpiryPanel,
  OutcomeMixPanel,
  SlaPanel,
  VolumePanel,
} from '../../core/api/models';
import { AuthService } from '../../core/auth/auth.service';
import { ReviewQueueStateService } from '../review/review-queue-state.service';
import { countOf, formatHours, formatPercent, percentWidth, rangeSince, segmentWidth, type RangePreset } from './dashboard.model';

type Status = 'loading' | 'loaded' | 'error';

interface Panel<T> {
  readonly status: Status;
  readonly data: T | null;
  readonly error: string | null;
}

function initialPanel<T>(): Panel<T> {
  return { status: 'loading', data: null, error: null };
}

/**
 * [7] Dashboard — Auditor and Management.
 *
 * **Every number that has a real row-level home links through to it.**
 * There is no "all assessments" or "all findings" screen of its own — the
 * only rows-level destination reachable from here is the Review Queue
 * (`/review`, `Capability.VIEW_QUEUE`: reviewer/approver/auditor). An Admin
 * viewing this dashboard (`view_dashboard` also grants admin) does NOT hold
 * `view_queue`, so every drill-through link below is rendered as plain,
 * non-interactive text for a viewer who lacks that capability — a courtesy
 * link into a guaranteed 403 is worse than no link (mirrors this task's
 * Assessment Result finding on the risk-acceptance download button).
 * Drill-through reuses {@link ReviewQueueStateService} (the same
 * `providedIn: 'root'` singleton the Review Queue itself reads its
 * filters from) rather than URL query params: setting the shared filter
 * state before navigating is exactly what the queue already listens for.
 *
 * **The Determination Expiry panel's numbers do not link anywhere, and this
 * is a genuine backend gap, not an oversight.** `lapsing_within_7_days`/
 * `already_expired` are ASSESSMENT-level facts (`Assessment.expires_at`).
 * The Review Queue is finding-level and carries no expiry filter at all;
 * the one assessment-level list endpoint, `GET /api/assessments`, returns
 * only the CALLER's own assessments (`app/api/assessments.py::list_my_assessments`
 * — no capability exists for "every assessment", and an Auditor holds no
 * `raise_assessment` capability to reach `/assessments` even if it did).
 * Flagged in the task report: ui-spec's "every number links through to the
 * underlying findings" cannot hold universally without either an
 * assessment-list endpoint scoped to Auditor/Admin, or an expiry filter on
 * the Review Queue.
 *
 * **The Volume panel does not show a weekly trend, unlike the mockup's bar
 * chart.** `GET /api/dashboard/volume` (`app/api/dashboard.py`) returns ONE
 * aggregate for the whole `[since, until]` window — `findings_by_outcome`
 * is a flat count map, not a time series, and no endpoint anywhere buckets
 * by week. Rendered honestly as one stacked bar for the whole window
 * rather than inventing weekly buckets the API cannot back.
 *
 * **The application filter has no `GET /api/applications` to populate it
 * from** (that route is `Capability.RAISE_ASSESSMENT` — requester-only, the
 * same finding Task 3's report made for the Review Queue). Its option list
 * is instead accumulated from whatever `application_id`s the Outcome Mix
 * panel has actually returned, the same courtesy the Review Queue and Risk
 * Acceptance Queue use.
 */
@Component({
  selector: 'app-dashboard',
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './dashboard.html',
})
export class Dashboard {
  private readonly api = inject(DashboardApiService);
  private readonly router = inject(Router);
  private readonly auth = inject(AuthService);
  private readonly queueState = inject(ReviewQueueStateService);

  protected readonly rangePreset = signal<RangePreset>(30);
  protected readonly applicationFilter = signal<string>('all');

  protected readonly volume = signal<Panel<VolumePanel>>(initialPanel());
  protected readonly automationSplit = signal<Panel<AutomationSplitPanel>>(initialPanel());
  protected readonly sla = signal<Panel<SlaPanel>>(initialPanel());
  protected readonly agreement = signal<Panel<AgreementPanel>>(initialPanel());
  protected readonly outcomeMix = signal<Panel<OutcomeMixPanel>>(initialPanel());
  protected readonly expiry = signal<Panel<ExpiryPanel>>(initialPanel());

  protected readonly applicationOptions = computed(() => {
    const rows = this.outcomeMix().data?.by_application ?? [];
    return Array.from(new Set(rows.map((r) => r.application_id))).sort();
  });

  protected readonly canDrillIntoQueue = computed(() => this.auth.hasCapability('view_queue'));
  protected readonly belowBarRuleCount = computed(
    () => (this.agreement().data?.rules ?? []).filter((r) => r.below_bar).length,
  );

  protected readonly formatPercent = formatPercent;
  protected readonly formatHours = formatHours;
  protected readonly percentWidth = percentWidth;
  protected readonly segmentWidth = segmentWidth;
  protected readonly countOf = countOf;

  constructor() {
    void this.reloadAll();
  }

  private rangeQuery(): DashboardRangeQuery {
    const now = new Date();
    const query: DashboardRangeQuery = { since: rangeSince(this.rangePreset(), now), until: now.toISOString() };
    if (this.applicationFilter() !== 'all') query.application_id = this.applicationFilter();
    return query;
  }

  protected onRangeChange(value: string): void {
    this.rangePreset.set(Number(value) as RangePreset);
    void this.reloadAll();
  }

  protected onApplicationChange(value: string): void {
    this.applicationFilter.set(value);
    void this.reloadAll();
  }

  private async reloadAll(): Promise<void> {
    // Every panel loads and fails independently — "one failed panel must
    // not blank the page" (ui-spec). Each `loadPanel` call below owns only
    // its own signal.
    void this.loadPanel(this.volume, () => this.api.volume(this.rangeQuery()));
    void this.loadPanel(this.automationSplit, () => this.api.automationSplit(this.rangeQuery()));
    void this.loadPanel(this.sla, () => this.api.sla(this.rangeQuery()));
    void this.loadPanel(this.agreement, () => this.api.agreement({ since: this.rangeQuery().since, until: this.rangeQuery().until }));
    void this.loadPanel(this.outcomeMix, () => this.api.outcomeMix(this.rangeQuery()));
    void this.loadPanel(this.expiry, () => this.api.expiry({ application_id: this.rangeQuery().application_id }));
  }

  private async loadPanel<T>(target: { set(v: Panel<T>): void }, fetch: () => Observable<T>): Promise<void> {
    target.set(initialPanel());
    try {
      const data = await firstValueFrom(fetch());
      target.set({ status: 'loaded', data, error: null });
    } catch (error) {
      target.set({ status: 'error', data: null, error: Dashboard.messageFor(error) });
    }
  }

  protected retryVolume(): void {
    void this.loadPanel(this.volume, () => this.api.volume(this.rangeQuery()));
  }
  protected retryAutomationSplit(): void {
    void this.loadPanel(this.automationSplit, () => this.api.automationSplit(this.rangeQuery()));
  }
  protected retrySla(): void {
    void this.loadPanel(this.sla, () => this.api.sla(this.rangeQuery()));
  }
  protected retryAgreement(): void {
    void this.loadPanel(this.agreement, () => this.api.agreement({ since: this.rangeQuery().since, until: this.rangeQuery().until }));
  }
  protected retryOutcomeMix(): void {
    void this.loadPanel(this.outcomeMix, () => this.api.outcomeMix(this.rangeQuery()));
  }
  protected retryExpiry(): void {
    void this.loadPanel(this.expiry, () => this.api.expiry({ application_id: this.rangeQuery().application_id }));
  }

  // --- Drill-through: set the Review Queue's shared filter state, then
  // navigate — never a link the server will 403.

  protected drillOutcome(outcome: 'not_affected' | 'affected' | 'needs_review' | 'risk_acceptance_required'): void {
    if (!this.canDrillIntoQueue()) return;
    this.queueState.clearFilters();
    this.queueState.setOutcome(outcome);
    void this.router.navigateByUrl('/review');
  }

  protected drillBreaching(): void {
    if (!this.canDrillIntoQueue()) return;
    this.queueState.clearFilters();
    this.queueState.setOutcome('needs_review');
    this.queueState.setSla('breaching');
    void this.router.navigateByUrl('/review');
  }

  protected drillTier(tier: EvidenceTier): void {
    if (!this.canDrillIntoQueue()) return;
    this.queueState.clearFilters();
    this.queueState.setTier(tier);
    void this.router.navigateByUrl('/review');
  }

  protected drillApplication(applicationId: string): void {
    if (!this.canDrillIntoQueue()) return;
    this.queueState.clearFilters();
    this.queueState.setApplication(applicationId);
    void this.router.navigateByUrl('/review');
  }

  protected drillAll(): void {
    if (!this.canDrillIntoQueue()) return;
    this.queueState.clearFilters();
    this.queueState.setOutcome('all');
    void this.router.navigateByUrl('/review');
  }

  private static messageFor(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (typeof error.error?.detail === 'string') return error.error.detail;
      if (error.status === 0) return 'The portal is unreachable.';
    }
    return 'Could not load this panel.';
  }
}
