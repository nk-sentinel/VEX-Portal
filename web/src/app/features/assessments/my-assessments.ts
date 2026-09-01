import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';

import { AssessmentsApiService } from '../../core/api';
import type { AssessmentState, AssessmentSummary } from '../../core/api/models';
import { OUTCOME_META, expiryBand, expiryClass, expiryLabel, formatRelativeAge, stateBadgeClass, stateLabel } from './assessments.model';

type PageState = 'loading' | 'error' | 'empty' | 'normal';
type StateFilter = 'all' | AssessmentState;

/**
 * [3] My Assessments — the requester's own requests, assessment-level rows.
 *
 * **The mockup's "collecting evidence 8/12" fractional progress on an
 * `ANALYSING` row has no data source, and in practice `ANALYSING` is a
 * state this screen will essentially never observe.** `POST /api/assessments`
 * runs admission AND the whole determination pipeline inside one request
 * (see `new-assessment.ts`'s docstring); `AssessmentState.ANALYSING` is set
 * on the in-memory row only transiently, before
 * `app/api/assessments.py::recompute_assessment_state` overwrites it to
 * `NEEDS_REVIEW`/`COMPLETED` in the SAME transaction that eventually
 * commits — no reader outside that request can observe the assessment
 * sitting at `ANALYSING`, let alone a per-collector fraction (no such field
 * exists on `AssessmentSummary` either way). Rendered defensively (the enum
 * value is real and a future async pipeline could reach it), but as an
 * indeterminate "Analysing…" label, never a fabricated "N/M" count.
 */
@Component({
  selector: 'app-my-assessments',
  imports: [FormsModule, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './my-assessments.html',
})
export class MyAssessments {
  private readonly api = inject(AssessmentsApiService);
  private readonly router = inject(Router);

  protected readonly pageState = signal<PageState>('loading');
  protected readonly loadErrorMessage = signal<string | null>(null);
  protected readonly assessments = signal<AssessmentSummary[]>([]);
  protected readonly now = signal(new Date());

  protected readonly stateFilter = signal<StateFilter>('all');
  protected readonly applicationFilter = signal<string>('all');

  protected readonly applicationOptions = computed(() => {
    const apps = new Set(this.assessments().map((a) => a.application_id));
    return Array.from(apps).sort();
  });

  protected readonly isFiltered = computed(() => this.stateFilter() !== 'all' || this.applicationFilter() !== 'all');

  protected readonly filteredRows = computed(() =>
    this.assessments().filter((a) => {
      if (this.stateFilter() !== 'all' && a.state !== this.stateFilter()) return false;
      if (this.applicationFilter() !== 'all' && a.application_id !== this.applicationFilter()) return false;
      return true;
    }),
  );

  protected readonly OUTCOME_META = OUTCOME_META;
  protected readonly stateBadgeClass = stateBadgeClass;
  protected readonly stateLabel = stateLabel;
  protected readonly expiryClass = (row: AssessmentSummary) => expiryClass(expiryBand(row.expires_at, this.now()));
  protected readonly expiryText = (row: AssessmentSummary) => expiryLabel(row.expires_at, this.now());
  protected readonly ageText = (row: AssessmentSummary) => formatRelativeAge(row.submitted_at ?? row.created_at, this.now());

  constructor() {
    void this.load();
  }

  private async load(): Promise<void> {
    this.pageState.set('loading');
    this.now.set(new Date());
    try {
      const assessments = await firstValueFrom(this.api.listMyAssessments());
      this.assessments.set(assessments);
      this.pageState.set(assessments.length === 0 ? 'empty' : 'normal');
    } catch (error) {
      this.loadErrorMessage.set(MyAssessments.messageFor(error));
      this.pageState.set('error');
    }
  }

  protected retry(): void {
    void this.load();
  }

  protected clearFilters(): void {
    this.stateFilter.set('all');
    this.applicationFilter.set('all');
  }

  protected openRow(id: string): void {
    void this.router.navigate(['/assessments', id, 'result']);
  }

  /** ui-spec: prefilled application + note; a FRESH report and artifact are required, per the class docstring's expiry-reassessment rule. */
  protected raiseReassessment(row: AssessmentSummary, event: Event): void {
    event.stopPropagation();
    void this.router.navigate(['/assessments/new'], {
      queryParams: { applicationId: row.application_id, note: row.requester_note ?? '' },
    });
  }

  /** ui-spec: prefilled with the previous inputs the list endpoint actually carries (application, report id, note) — see `new-assessment.ts`'s prefill docstring on why artifact/commit are not included. */
  protected fixAndResubmit(row: AssessmentSummary, event: Event): void {
    event.stopPropagation();
    void this.router.navigate(['/assessments/new'], {
      queryParams: { applicationId: row.application_id, reportRef: row.report_id, note: row.requester_note ?? '' },
    });
  }

  private static messageFor(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (typeof error.error?.detail === 'string') return error.error.detail;
      if (error.status === 0) return 'The portal is unreachable.';
    }
    return 'Could not load your assessments.';
  }
}
