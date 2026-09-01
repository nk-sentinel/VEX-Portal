import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';

import { AssessmentsApiService } from '../../core/api';
import type { AdmissionCheckKind, ApplicationOut } from '../../core/api/models';
import { ADMISSION_CHECK_LABEL, checkOrder, extractReportId } from './assessments.model';

type LoadState = 'loading' | 'ready' | 'empty' | 'error';
type ArtifactType = 'binary' | 'image';
type CheckStatus = 'pending' | 'pass' | 'fail';

interface CheckRow {
  readonly check: AdmissionCheckKind;
  readonly status: CheckStatus;
}

interface AdmissionFailure {
  readonly check: AdmissionCheckKind;
  readonly message: string;
}

/**
 * [2] New Assessment.
 *
 * **No per-field live admission checks exist in this backend, unlike the
 * mockup's "spinner on blur" per field.** `POST /api/assessments`
 * (`backend/app/api/assessments.py::raise_assessment`) is the ONLY write
 * endpoint: it runs admission (report -> artifact -> provenance, stopping at
 * the first failure) AND, on success, the entire determination pipeline —
 * synchronously, inside the one request. There is no
 * `GET`/preview endpoint to validate the report URL or artifact reference
 * independently while the requester is still typing, and no way to observe
 * an intermediate `ANALYSING` state afterward either (the assessment's state
 * is recomputed to `NEEDS_REVIEW`/`COMPLETED` before the same transaction
 * commits — see `recompute_assessment_state`). Flagged in the task report as
 * a genuine backend gap, not silently reconciled: the mockup's "form stays
 * usable while checks run in the background, one field at a time" experience
 * is not implementable against this API today.
 *
 * What IS implementable, and what this component does: submit runs the
 * whole pipeline in one request; a 422 response carries exactly which of the
 * three checks failed and an actionable message
 * (`AdmissionFailureOut.check`/`.message` — the server's own wording already
 * satisfies ui-spec's "fail message must say..." table). Checks are ordered
 * (report, artifact, provenance) and fail-fast server-side, so a failure at
 * check N implies every check before it passed — {@link CheckRow} renders
 * that inference, never fabricating a livelier picture than the API
 * supports. A provenance failure is rendered as the spec's hard stop: the
 * Submit button is disabled again until the artifact coordinate is actually
 * edited, never merely re-clickable past the same warning.
 *
 * **The mockup's "Branch assessed" field has no backend counterpart —
 * dropped, not faked.** Neither `RaiseAssessmentRequest` nor the `Assessment`
 * table (`backend/app/repos/models.py`) carries a branch column; only
 * `commit_sha` exists, and it is not itself cross-checked against
 * `git.properties` by `admission.py::admit` (which does not even accept a
 * commit parameter) — the commit/`git.properties` comparison ui-spec shows
 * inline in the form is, in this codebase, a post-hoc fact surfaced on
 * screens 4/6 from `AssessmentDetail.provenance` (see `assessment-result.ts`),
 * never a live check here. Same category of finding as Task 1/2's SSO button
 * and Task 3's degraded-collector rendering: built to what the backend can
 * actually do, flagged rather than invented.
 */
@Component({
  selector: 'app-new-assessment',
  imports: [FormsModule, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './new-assessment.html',
})
export class NewAssessment {
  private readonly api = inject(AssessmentsApiService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  protected readonly loadState = signal<LoadState>('loading');
  protected readonly loadErrorMessage = signal<string | null>(null);
  protected readonly applications = signal<ApplicationOut[]>([]);

  protected readonly applicationId = signal('');
  protected readonly reportRef = signal('');
  protected readonly artifactType = signal<ArtifactType>('image');
  protected readonly artifactCoordinates = signal('');
  protected readonly commitSha = signal('');
  protected readonly requesterNote = signal('');

  protected readonly submitting = signal(false);
  protected readonly submitError = signal<string | null>(null);
  protected readonly admissionFailure = signal<AdmissionFailure | null>(null);
  /** The artifact value at the moment a provenance mismatch fired — Submit stays blocked until this no longer matches, so the hard stop cannot be clicked past unchanged. */
  private readonly provenanceBlockedArtifact = signal<string | null>(null);

  protected readonly checkRows = computed<CheckRow[]>(() => {
    const failure = this.admissionFailure();
    const order: AdmissionCheckKind[] = ['report', 'artifact', 'provenance'];
    if (!failure) return order.map((check) => ({ check, status: 'pending' }));
    const failedOrder = checkOrder(failure.check);
    return order.map((check) => {
      if (checkOrder(check) < failedOrder) return { check, status: 'pass' };
      if (check === failure.check) return { check, status: 'fail' };
      return { check, status: 'pending' };
    });
  });

  protected readonly isProvenanceBlocked = computed(
    () =>
      this.admissionFailure()?.check === 'provenance' &&
      this.artifactCoordinates() === this.provenanceBlockedArtifact(),
  );

  protected readonly canSubmit = computed(
    () =>
      !this.submitting() &&
      !this.isProvenanceBlocked() &&
      this.applicationId().trim() !== '' &&
      this.reportRef().trim() !== '' &&
      this.artifactCoordinates().trim() !== '' &&
      this.requesterNote().trim() !== '',
  );

  protected readonly ADMISSION_CHECK_LABEL = ADMISSION_CHECK_LABEL;

  constructor() {
    void this.loadApplications();
    this.applyPrefill();
  }

  /**
   * [3]'s two row actions prefill whichever of these query params they have
   * to hand — "Fix and resubmit" (admission-failed row) sends `reportRef`
   * (the previous report id, from `AssessmentSummary.report_id`); "Raise
   * reassessment" (expired row) deliberately does NOT, per ui-spec:
   * "requiring a fresh report URL and artifact" for a reassessment, since
   * the previous determination lapsed and re-admitting the exact same
   * inputs proves nothing new. Neither sends artifact/commit —
   * `AssessmentSummary` (the list endpoint [3] reads) never carries them;
   * only `AssessmentDetail` does, and fetching that just to prefill a
   * field the requester likely has to re-enter anyway (it is very often
   * the artifact that failed) was not worth the extra round trip.
   */
  private applyPrefill(): void {
    const params = this.route.snapshot.queryParamMap;
    const applicationId = params.get('applicationId');
    if (applicationId) this.applicationId.set(applicationId);
    const note = params.get('note');
    if (note) this.requesterNote.set(note);
    const reportRef = params.get('reportRef');
    if (reportRef) this.reportRef.set(reportRef);
  }

  private async loadApplications(): Promise<void> {
    this.loadState.set('loading');
    try {
      const applications = await firstValueFrom(this.api.listApplications());
      this.applications.set(applications);
      this.loadState.set(applications.length === 0 ? 'empty' : 'ready');
    } catch (error) {
      this.loadErrorMessage.set(NewAssessment.messageFor(error));
      this.loadState.set('error');
    }
  }

  protected retryLoad(): void {
    void this.loadApplications();
  }

  protected setArtifactType(type: ArtifactType): void {
    this.artifactType.set(type);
  }

  protected artifactPlaceholder(): string {
    return this.artifactType() === 'binary'
      ? 'artifactory.example.com/libs-release/payments-api-1.14.2.jar'
      : 'artifactory.example.com/payments-api:1.14.2';
  }

  /** The hard-stop's only way forward — clears the artifact so a resubmit is provably a different value, not a click past the same warning. */
  protected useDifferentArtifact(): void {
    this.artifactCoordinates.set('');
    this.provenanceBlockedArtifact.set(null);
    this.admissionFailure.set(null);
  }

  protected async submit(): Promise<void> {
    if (!this.canSubmit()) return;
    this.submitting.set(true);
    this.submitError.set(null);
    this.admissionFailure.set(null);
    try {
      const detail = await firstValueFrom(
        this.api.raiseAssessment({
          application_id: this.applicationId(),
          report_id: extractReportId(this.reportRef()),
          artifact_coordinates: this.artifactCoordinates().trim(),
          commit_sha: this.commitSha().trim() || null,
          requester_note: this.requesterNote().trim(),
        }),
      );
      await this.router.navigate(['/assessments', detail.id, 'result']);
    } catch (error) {
      this.handleSubmitError(error);
    } finally {
      this.submitting.set(false);
    }
  }

  private handleSubmitError(error: unknown): void {
    if (error instanceof HttpErrorResponse) {
      const detail = error.error?.detail;
      if (error.status === 422 && detail && typeof detail === 'object' && 'check' in detail) {
        const failure = detail as AdmissionFailure;
        this.admissionFailure.set(failure);
        if (failure.check === 'provenance') this.provenanceBlockedArtifact.set(this.artifactCoordinates());
        return;
      }
      if (error.status === 503) {
        this.submitError.set(typeof detail === 'string' ? detail : 'Nexus IQ is unreachable. Try again shortly.');
        return;
      }
      if (error.status === 502) {
        this.submitError.set(
          'Admission passed, but evidence collection failed straight after it. Nothing was determined — try submitting again.',
        );
        return;
      }
      if (error.status === 403) {
        this.submitError.set('You do not have access to this application in Nexus IQ.');
        return;
      }
    }
    this.submitError.set('Could not submit the assessment. Try again.');
  }

  private static messageFor(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (typeof error.error?.detail === 'string') return error.error.detail;
      if (error.status === 503) return 'Nexus IQ is unreachable.';
    }
    return 'Could not load your applications.';
  }
}
