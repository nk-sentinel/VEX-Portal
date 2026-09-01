import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import type { Observable } from 'rxjs';

import { toHttpParams } from './http-params';
import type {
  AgreementPanel,
  AutomationSplitPanel,
  DashboardRangeQuery,
  ExpiryPanel,
  OutcomeMixPanel,
  SlaPanel,
  VolumePanel,
} from './models';

/**
 * [7] Dashboard's six panels. Every panel is filterable by date range and
 * application (`docs/design/ui-spec.md`: "every number links through to
 * the underlying findings" — the drill-through itself is drawn but not
 * wired per that spec's "Still open" section; this service only fetches
 * the panel data).
 */
@Injectable({ providedIn: 'root' })
export class DashboardApiService {
  private readonly http = inject(HttpClient);

  volume(query?: DashboardRangeQuery): Observable<VolumePanel> {
    return this.http.get<VolumePanel>('/api/dashboard/volume', { params: toHttpParams(query) });
  }

  /** "The headline number for whether the portal is working." */
  automationSplit(query?: DashboardRangeQuery): Observable<AutomationSplitPanel> {
    return this.http.get<AutomationSplitPanel>('/api/dashboard/automation-split', {
      params: toHttpParams(query),
    });
  }

  sla(query?: DashboardRangeQuery): Observable<SlaPanel> {
    return this.http.get<SlaPanel>('/api/dashboard/sla', { params: toHttpParams(query) });
  }

  /** "The trust metric" — no `application_id` filter; agreement is per-rule, portal-wide. */
  agreement(query?: Pick<DashboardRangeQuery, 'since' | 'until'>): Observable<AgreementPanel> {
    return this.http.get<AgreementPanel>('/api/dashboard/agreement', { params: toHttpParams(query) });
  }

  outcomeMix(query?: DashboardRangeQuery): Observable<OutcomeMixPanel> {
    return this.http.get<OutcomeMixPanel>('/api/dashboard/outcome-mix', { params: toHttpParams(query) });
  }

  /** "Incoming reassessment load" — the only panel with no date-range filter. */
  expiry(query?: Pick<DashboardRangeQuery, 'application_id'>): Observable<ExpiryPanel> {
    return this.http.get<ExpiryPanel>('/api/dashboard/expiry', { params: toHttpParams(query) });
  }
}
