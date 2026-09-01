import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import type { Observable } from 'rxjs';

import type { HandoffStatusUpdate, RiskAcceptanceRow } from './models';

/**
 * [8] Risk Acceptance Queue. Every row here received NO determination — the
 * IQ violation stays open. The status this service writes is recorded only;
 * the portal never enforces or acts on it
 * (`docs/design/ui-spec.md` screen 8).
 */
@Injectable({ providedIn: 'root' })
export class RiskAcceptanceApiService {
  private readonly http = inject(HttpClient);

  /** Only `RISK_ACCEPTANCE_REQUIRED` findings ever appear here. */
  list(): Observable<RiskAcceptanceRow[]> {
    return this.http.get<RiskAcceptanceRow[]>('/api/risk-acceptance');
  }

  /** Manually set by the risk manager — the portal only records this. */
  updateStatus(findingId: string, body: HandoffStatusUpdate): Observable<RiskAcceptanceRow> {
    return this.http.put<RiskAcceptanceRow>(
      `/api/risk-acceptance/${encodeURIComponent(findingId)}/status`,
      body,
    );
  }

  /**
   * The self-contained evidence document the app team takes to their risk
   * manager. No GRC integration — a deliberate hand-off, tracked only to
   * the point of leaving the portal. `app/api/risk.py`'s `download_package`
   * returns the JSON body with `Content-Disposition: attachment`, so the
   * browser downloads it as a file rather than this client parsing it —
   * this method returns the URL for a caller to put on an `<a href>` (or
   * fetch as a blob) rather than an `Observable<T>` of parsed JSON.
   */
  downloadPackageUrl(findingId: string): string {
    return `/api/risk-acceptance/${encodeURIComponent(findingId)}/package`;
  }
}
