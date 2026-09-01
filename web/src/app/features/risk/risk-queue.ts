import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { firstValueFrom } from 'rxjs';

import { RiskAcceptanceApiService } from '../../core/api';
import type { HandoffStatus, RiskAcceptanceRow } from '../../core/api/models';
import { AuthService } from '../../core/auth/auth.service';
import { formatAge } from '../review/review.model';
import { EvidenceDrawer } from '../review/evidence-drawer';
import { HANDOFF_META, HANDOFF_ORDER } from './risk.model';

type PageState = 'loading' | 'error' | 'empty' | 'normal';

/**
 * [8] Risk Acceptance Queue — Risk Manager.
 *
 * **Every row here received NO determination; the Nexus IQ violation stays
 * open.** `RiskAcceptanceApiService.list()` only ever returns
 * `RISK_ACCEPTANCE_REQUIRED` findings (`app/api/risk.py`'s own docstring:
 * "the whole point of the outcome existing at all" — CLAUDE.md rule 5), so
 * this screen has no need to filter by outcome; the permanent callout above
 * the table is the reminder that nothing below it is resolved.
 *
 * **The Evidence Drawer opens on row click ONLY for a viewer who holds
 * `view_queue`.** ui-spec draws the drawer as a read-only overlay on this
 * screen ("Risk Manager -> [8] -> ((EVIDENCE DRAWER, read-only))"), but the
 * only endpoint that serves the drawer's payload,
 * `GET /api/review/findings/{id}` (`app/api/review.py::get_finding`),
 * requires `Capability.VIEW_QUEUE` — whose roster is reviewer/approver/
 * auditor. `risk_manager`, this screen's own primary role, is NOT in that
 * list: a risk manager opening the drawer would get a 403. Flagged in the
 * task report as a genuine spec/backend conflict, same family as Assessment
 * Result's package-download gap. Rather than open a drawer that 403s for
 * the role the screen is built for, rows are only clickable for a viewer
 * who actually holds `view_queue` (i.e. an Auditor watching this queue,
 * per `app/api/risk.py`'s own docstring on who may watch vs write) — a
 * Risk Manager instead relies on "Download evidence package" (which they
 * DO hold the capability for) to see the underlying evidence.
 */
@Component({
  selector: 'app-risk-queue',
  imports: [FormsModule, EvidenceDrawer],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './risk-queue.html',
})
export class RiskQueue {
  private readonly api = inject(RiskAcceptanceApiService);
  protected readonly auth = inject(AuthService);

  protected readonly pageState = signal<PageState>('loading');
  protected readonly loadErrorMessage = signal<string | null>(null);
  protected readonly rows = signal<RiskAcceptanceRow[]>([]);
  protected readonly openFindingId = signal<string | null>(null);
  protected readonly savingId = signal<string | null>(null);
  protected readonly saveError = signal<string | null>(null);

  protected readonly canManage = computed(() => this.auth.hasCapability('manage_risk_acceptance'));
  protected readonly canOpenDrawer = computed(() => this.auth.hasCapability('view_queue'));

  protected readonly HANDOFF_META = HANDOFF_META;
  protected readonly HANDOFF_ORDER = HANDOFF_ORDER;
  protected readonly formatAge = formatAge;

  constructor() {
    void this.load();
  }

  private async load(): Promise<void> {
    this.pageState.set('loading');
    try {
      const rows = await firstValueFrom(this.api.list());
      this.rows.set(rows);
      this.pageState.set(rows.length === 0 ? 'empty' : 'normal');
    } catch (error) {
      this.loadErrorMessage.set(RiskQueue.messageFor(error));
      this.pageState.set('error');
    }
  }

  protected retry(): void {
    void this.load();
  }

  protected openRow(findingId: string): void {
    if (!this.canOpenDrawer()) return;
    this.openFindingId.set(findingId);
  }

  protected closeDrawer(): void {
    this.openFindingId.set(null);
  }

  protected packageUrl(findingId: string): string {
    return this.api.downloadPackageUrl(findingId);
  }

  protected async updateStatus(row: RiskAcceptanceRow, status: HandoffStatus): Promise<void> {
    if (!this.canManage() || status === row.status) return;
    this.savingId.set(row.finding_id);
    this.saveError.set(null);
    try {
      const updated = await firstValueFrom(this.api.updateStatus(row.finding_id, { status }));
      this.rows.update((rows) => rows.map((r) => (r.finding_id === updated.finding_id ? updated : r)));
    } catch (error) {
      this.saveError.set(RiskQueue.messageFor(error));
    } finally {
      this.savingId.set(null);
    }
  }

  private static messageFor(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (typeof error.error?.detail === 'string') return error.error.detail;
      if (error.status === 0) return 'The portal is unreachable.';
    }
    return 'That did not work. Try again.';
  }
}
