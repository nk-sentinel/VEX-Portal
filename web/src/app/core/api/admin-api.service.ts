import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import type { Observable } from 'rxjs';

import type { RuleOut, RuleUpdateRequest, RuleUpdateResult } from './models';

/**
 * [9] Rules & Thresholds. `RuleOut` is a union of three shapes
 * (`ToggleableRuleOut | EscalationRuleOut | PendingRuleOut`) discriminated
 * by `has_auto_determination_toggle` (`true`/`false`) or its absence — a
 * Tier 3 rule genuinely carries no toggle field at all, which is why the UI
 * must render nothing there rather than a disabled control
 * (`docs/design/ui-spec.md`: "Not disabled — absent, because the capability
 * does not exist.").
 */
@Injectable({ providedIn: 'root' })
export class AdminApiService {
  private readonly http = inject(HttpClient);

  listRules(): Observable<RuleOut[]> {
    return this.http.get<RuleOut[]>('/api/admin/rules');
  }

  /**
   * A change to one rule's configuration. `auto_determination_enabled` is
   * refused (422) server-side for a Tier 3 rule id — this client does not
   * pre-validate that; it is the server's job (rule 3).
   */
  updateRule(ruleId: string, body: RuleUpdateRequest): Observable<RuleUpdateResult> {
    return this.http.put<RuleUpdateResult>(`/api/admin/rules/${encodeURIComponent(ruleId)}`, body);
  }
}
