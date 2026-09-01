import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';

import { AssessmentsApiService, RiskAcceptanceApiService } from '../../core/api';
import type { AssessmentDetail } from '../../core/api/models';
import { AuthService } from '../../core/auth/auth.service';
import { OUTCOME_META, formatAge, stateBadgeClass, stateLabel, tierBadgeClass, tierLabel } from './assessments.model';

type PageState = 'loading' | 'error' | 'loaded';

/**
 * [4] Assessment Result — read-only outcome for the requester.
 *
 * **"Download evidence package" is gated by `view_risk_acceptance`
 * (risk_manager/auditor) — a Requester almost never holds it.** ui-spec
 * says plainly: "Findings marked Risk Acceptance Required carry an explicit
 * next step... with a package download", on the REQUESTER's own screen. But
 * the only implementation of that download,
 * `GET /api/risk-acceptance/{finding_id}/package`
 * (`backend/app/api/risk.py::download_package`), requires
 * `Capability.VIEW_RISK_ACCEPTANCE`, whose roster is `risk_manager` and
 * `auditor` — `requester` is not in it. A Requester who clicks that button
 * would get a 403, not a file. Flagged in the task report as a genuine
 * backend/spec conflict, same family as Task 3's Concern #5 (the drawer
 * already had to gate the same link away from Reviewer/Approver for the
 * same reason). Rather than ship a button that always fails for its
 * intended audience, this component gates it on the real capability — most
 * requesters will instead see an explanatory line naming who can pull the
 * package. The honest fix is a requester-scoped download route (the
 * requester already has everything else needed to see this finding); not
 * built here since it is outside this task's file scope
 * (`web/src/app/features/assessments/`) and touches the backend.
 */
@Component({
  selector: 'app-assessment-result',
  imports: [RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './assessment-result.html',
})
export class AssessmentResult {
  private readonly api = inject(AssessmentsApiService);
  private readonly riskApi = inject(RiskAcceptanceApiService);
  private readonly route = inject(ActivatedRoute);
  protected readonly auth = inject(AuthService);

  protected readonly assessmentId = this.route.snapshot.paramMap.get('id')!;

  protected readonly pageState = signal<PageState>('loading');
  protected readonly loadErrorMessage = signal<string | null>(null);
  protected readonly assessment = signal<AssessmentDetail | null>(null);
  protected readonly expandedIds = signal<ReadonlySet<string>>(new Set());

  protected readonly canDownloadPackage = computed(() => this.auth.hasCapability('view_risk_acceptance'));

  protected readonly OUTCOME_META = OUTCOME_META;
  protected readonly tierBadgeClass = tierBadgeClass;
  protected readonly tierLabel = tierLabel;
  protected readonly formatAge = formatAge;
  protected readonly stateBadgeClass = stateBadgeClass;
  protected readonly stateLabel = stateLabel;

  constructor() {
    void this.load();
  }

  private async load(): Promise<void> {
    this.pageState.set('loading');
    try {
      const detail = await firstValueFrom(this.api.getAssessment(this.assessmentId));
      this.assessment.set(detail);
      this.pageState.set('loaded');
    } catch (error) {
      this.loadErrorMessage.set(AssessmentResult.messageFor(error));
      this.pageState.set('error');
    }
  }

  protected retry(): void {
    void this.load();
  }

  protected isExpanded(findingId: string): boolean {
    return this.expandedIds().has(findingId);
  }

  protected toggleEvidence(findingId: string): void {
    const next = new Set(this.expandedIds());
    if (next.has(findingId)) next.delete(findingId);
    else next.add(findingId);
    this.expandedIds.set(next);
  }

  protected packageUrl(findingId: string): string {
    return this.riskApi.downloadPackageUrl(findingId);
  }

  private static messageFor(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (typeof error.error?.detail === 'string') return error.error.detail;
      if (error.status === 404) return 'That assessment does not exist, or you may not view it.';
      if (error.status === 0) return 'The portal is unreachable.';
    }
    return 'Could not load this assessment.';
  }
}
