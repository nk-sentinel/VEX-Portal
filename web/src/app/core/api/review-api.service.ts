import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import type { Observable } from 'rxjs';

import { toHttpParams } from './http-params';
import type {
  DecideRequest,
  RecommendRequest,
  RecommendationRecorded,
  ReviewFindingDetail,
  ReviewFindingRow,
  ReviewFindingsQuery,
} from './models';

/**
 * The Review Queue / Assessment Detail table (screens 5 and 6 — "one
 * component, differently scoped": [6] is this same list with
 * `assessment_id` set) and the Evidence Drawer's read/write actions.
 */
@Injectable({ providedIn: 'root' })
export class ReviewApiService {
  private readonly http = inject(HttpClient);

  /**
   * No filter is applied by default — the caller passes its own default
   * (e.g. the queue's "needs review" chip via `state`).
   */
  listFindings(query?: ReviewFindingsQuery): Observable<ReviewFindingRow[]> {
    return this.http.get<ReviewFindingRow[]>('/api/review/findings', {
      params: toHttpParams(query),
    });
  }

  /** The Evidence Drawer's full payload for one finding. */
  getFinding(findingId: string): Observable<ReviewFindingDetail> {
    return this.http.get<ReviewFindingDetail>(`/api/review/findings/${encodeURIComponent(findingId)}`);
  }

  /**
   * A reviewer's non-binding proposal. An audit entry only — never mutates
   * the finding or reaches IQ.
   */
  recommend(findingId: string, body: RecommendRequest): Observable<RecommendationRecorded> {
    return this.http.post<RecommendationRecorded>(
      `/api/review/findings/${encodeURIComponent(findingId)}/recommend`,
      body,
    );
  }

  /**
   * The approver's commit action — creates the IQ suppression for a
   * committed `not_affected`, nothing for a committed `affected`. The
   * server, not this client, enforces separation of duties and the Tier 2
   * second-confirmation rule; a rejected request surfaces as an HTTP error
   * for the caller to render, never something this method pre-checks.
   */
  decide(findingId: string, body: DecideRequest): Observable<ReviewFindingRow> {
    return this.http.post<ReviewFindingRow>(`/api/review/findings/${encodeURIComponent(findingId)}/decide`, body);
  }
}
