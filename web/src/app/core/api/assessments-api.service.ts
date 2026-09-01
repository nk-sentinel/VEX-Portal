import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import type { Observable } from 'rxjs';

import type { ApplicationOut, AssessmentDetail, AssessmentSummary, RaiseAssessmentRequest } from './models';

/**
 * `GET /api/applications`, and the assessment endpoints backing screens
 * [2] New Assessment, [3] My Assessments and [4] Assessment Result.
 */
@Injectable({ providedIn: 'root' })
export class AssessmentsApiService {
  private readonly http = inject(HttpClient);

  /** [2]'s application select — scoped to the caller's own IQ entitlement. */
  listApplications(): Observable<ApplicationOut[]> {
    return this.http.get<ApplicationOut[]>('/api/applications');
  }

  /** [3] My Assessments — the caller's own, newest first. */
  listMyAssessments(): Observable<AssessmentSummary[]> {
    return this.http.get<AssessmentSummary[]>('/api/assessments');
  }

  /** [2]'s submit action. */
  raiseAssessment(body: RaiseAssessmentRequest): Observable<AssessmentDetail> {
    return this.http.post<AssessmentDetail>('/api/assessments', body);
  }

  /** [4] Assessment Result, and [6]'s header data. */
  getAssessment(assessmentId: string): Observable<AssessmentDetail> {
    return this.http.get<AssessmentDetail>(`/api/assessments/${encodeURIComponent(assessmentId)}`);
  }
}
