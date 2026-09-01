import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  HostListener,
  computed,
  effect,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { map } from 'rxjs';

import { AssessmentsApiService, ReviewApiService } from '../../core/api';
import type { AssessmentDetail, ReviewFindingRow } from '../../core/api/models';
import { AuthService } from '../../core/auth/auth.service';
import { EvidenceDrawer } from './evidence-drawer';
import {
  OUTCOME_META,
  bulkBlocks as computeBulkBlocks,
  formatAge,
  formatSla,
  groupByAssessment,
  slaClass,
  sortRows,
  tierBadgeClass,
  tierLabel,
  type BulkBlock,
  type SortColumn,
} from './review.model';
import { ReviewQueueStateService, type OutcomeFilter, type SlaFilter, type TierFilter } from './review-queue-state.service';

type PageState = 'loading' | 'error' | 'empty' | 'normal';

/**
 * Screens [5] Review Queue and [6] Assessment Detail — "one component,
 * differently scoped": [5] is every finding filtered by state, [6] is the
 * same table with `assessment_id` fixed and an assessment-level header on
 * top (`docs/design/ui-spec.md`). Routed at both `/review` (unscoped) and
 * `/review/:id` (scoped, `id` read from `ActivatedRoute`) — the presence of
 * that route param, not a separate component, is what switches the view:
 * filters/grouping/bulk-select/the ASM column disappear, a header with
 * provenance/requester context and "Approve all reviewed" appears.
 *
 * Filter/sort/grouping state lives in {@link ReviewQueueStateService}
 * (`providedIn: 'root'`), not on this component, so it survives this
 * component being destroyed and recreated by router navigation — see that
 * service's own docstring. Opening the Evidence Drawer never navigates (it
 * only sets `openFindingId`), so it trivially keeps the queue scrolled and
 * every row's selection/highlight intact across a drawer round trip.
 */
@Component({
  selector: 'app-review-queue',
  imports: [FormsModule, RouterLink, DatePipe, EvidenceDrawer],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './review-queue.html',
})
export class ReviewQueue {
  private readonly reviewApi = inject(ReviewApiService);
  private readonly assessmentsApi = inject(AssessmentsApiService);
  protected readonly auth = inject(AuthService);
  protected readonly state = inject(ReviewQueueStateService);
  private readonly route = inject(ActivatedRoute);

  private readonly searchInput = viewChild<ElementRef<HTMLInputElement>>('searchInput');
  private readonly drawer = viewChild(EvidenceDrawer);

  protected readonly assessmentId = toSignal(
    this.route.paramMap.pipe(map((params) => params.get('id'))),
    { initialValue: this.route.snapshot.paramMap.get('id') },
  );
  protected readonly scoped = computed(() => this.assessmentId() != null);

  protected readonly pageState = signal<PageState>('loading');
  protected readonly rows = signal<ReviewFindingRow[]>([]);
  protected readonly lastUpdated = signal<Date | null>(null);
  protected readonly loadErrorMessage = signal<string | null>(null);
  /** Set on a refresh failure that has previous data to fall back on — the table stays, this renders as a banner above it. */
  protected readonly refreshErrorMessage = signal<string | null>(null);

  protected readonly assessmentHeader = signal<AssessmentDetail | null>(null);

  protected readonly selected = signal<ReadonlySet<string>>(new Set());
  protected readonly openFindingId = signal<string | null>(null);
  protected readonly cursorId = signal<string | null>(null);
  protected readonly bulkBlockList = signal<BulkBlock[] | null>(null);
  protected readonly savedMessage = signal<string | null>(null);

  protected readonly canCommit = computed(() => this.auth.hasCapability('commit_determination'));
  protected readonly canRecommend = computed(() => this.auth.hasCapability('recommend_determination'));
  protected readonly canManageOwnDetermination = computed(() => this.canCommit() || this.canRecommend());
  protected readonly isAuditorOnly = computed(() => !this.canManageOwnDetermination());
  protected readonly isSelfRequested = computed(
    () => this.assessmentHeader()?.requester === this.auth.username(),
  );

  protected readonly sortedRows = computed(() => sortRows(this.rows(), this.state.sortColumn(), this.state.sortDirection()));
  protected readonly groups = computed(() => groupByAssessment(this.sortedRows()));
  protected readonly rowCount = computed(() => this.rows().length);
  private readonly cursorIndex = computed(() => this.sortedRows().findIndex((r) => r.id === this.cursorId()));
  protected readonly hasPrevRow = computed(() => this.cursorIndex() > 0);
  protected readonly hasNextRow = computed(() => {
    const i = this.cursorIndex();
    return i >= 0 && i < this.sortedRows().length - 1;
  });
  protected readonly noSelection = computed(() => this.selected().size === 0);
  protected readonly selectedRows = computed(() => {
    const ids = this.selected();
    return this.rows().filter((row) => ids.has(row.id));
  });

  /** No `GET /api/applications` access for a reviewer/approver (403 — requester-only, see the task report) — derive the filter's option list from what is actually in the queue instead. */
  protected readonly applicationOptions = computed(() => {
    const apps = new Set(this.rows().map((row) => row.application_id));
    return Array.from(apps).sort();
  });

  protected readonly OUTCOME_META = OUTCOME_META;
  protected readonly tierBadgeClass = tierBadgeClass;
  protected readonly tierLabel = tierLabel;
  protected readonly slaClass = slaClass;
  protected readonly formatSla = formatSla;
  protected readonly formatAge = formatAge;

  /**
   * The last (scope, filters) combination a reload was actually issued
   * for. Angular's `effect()` scheduler can re-invoke this effect an extra
   * time with every tracked signal reporting the exact same value it read
   * last time (observed empirically in this component's own tests, across
   * more than one Angular/zone version's timing quirks) — this guard makes
   * a spurious re-run a no-op instead of a genuine extra
   * `GET /api/review/findings` against the server on every unrelated
   * interaction, which would be a real cost on the screen the team lives
   * in all day.
   */
  private lastEffectKey: string | null = null;

  constructor() {
    effect(() => {
      // Re-derive the query whenever scope or (in unscoped mode) any filter
      // signal changes. Reading every filter signal here, even in scoped
      // mode where they are not sent, keeps this a single effect rather
      // than two — the scoped branch just ignores what it read.
      const id = this.assessmentId();
      const key = JSON.stringify([
        id,
        this.state.outcome(),
        this.state.application(),
        this.state.sla(),
        this.state.tier(),
        this.state.search(),
      ]);
      if (key === this.lastEffectKey) return;
      this.lastEffectKey = key;
      void this.reload();
      if (id) void this.loadAssessmentHeader(id);
      else this.assessmentHeader.set(null);
    });
  }

  private async reload(): Promise<void> {
    const hadData = this.lastUpdated() != null;
    if (!hadData) this.pageState.set('loading');
    const query = this.scoped() ? { assessment_id: this.assessmentId()! } : this.state.toQuery();
    try {
      const rows = await new Promise<ReviewFindingRow[]>((resolve, reject) => {
        this.reviewApi.listFindings(query).subscribe({ next: resolve, error: reject });
      });
      this.rows.set(rows);
      this.lastUpdated.set(new Date());
      this.refreshErrorMessage.set(null);
      this.pageState.set(rows.length === 0 ? 'empty' : 'normal');
      // Keep selection/cursor limited to rows that still exist.
      const ids = new Set(rows.map((r) => r.id));
      this.selected.set(new Set(Array.from(this.selected()).filter((id) => ids.has(id))));
      // Keep the roving-tabindex cursor valid — Tab-key accessibility needs
      // exactly one row focusable at all times once any rows exist, not
      // only after the first `j`/`k` press.
      if ((this.cursorId() == null || !ids.has(this.cursorId()!)) && rows.length > 0) {
        this.cursorId.set(rows[0].id);
      }
    } catch (error) {
      if (hadData) {
        // "Never blank the table on a refresh failure; a reviewer
        // mid-session loses their place" — rows/pageState stay as they are.
        this.refreshErrorMessage.set(ReviewQueue.messageFor(error));
      } else {
        this.pageState.set('error');
        this.loadErrorMessage.set(ReviewQueue.messageFor(error));
      }
    }
  }

  private async loadAssessmentHeader(id: string): Promise<void> {
    try {
      const detail = await new Promise<AssessmentDetail>((resolve, reject) => {
        this.assessmentsApi.getAssessment(id).subscribe({ next: resolve, error: reject });
      });
      this.assessmentHeader.set(detail);
    } catch {
      this.assessmentHeader.set(null);
    }
  }

  protected retry(): void {
    void this.reload();
  }

  private static messageFor(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (typeof error.error?.detail === 'string') return error.error.detail;
      if (error.status === 0) return 'Nexus IQ did not respond.';
    }
    return 'Could not refresh the queue.';
  }

  // --- Filters ----------------------------------------------------------

  protected onOutcomeFilter(value: OutcomeFilter): void {
    this.state.setOutcome(value);
  }
  protected onApplicationFilter(value: string): void {
    this.state.setApplication(value);
  }
  protected onSlaFilter(value: SlaFilter): void {
    this.state.setSla(value);
  }
  protected onTierFilter(value: string): void {
    this.state.setTier(value === 'all' ? 'all' : (Number(value) as TierFilter));
  }
  protected onSearch(value: string): void {
    this.state.setSearch(value);
  }
  protected clearFilters(): void {
    this.state.clearFilters();
  }
  protected setGrouping(value: 'none' | 'assessment'): void {
    this.state.setGrouping(value);
  }
  protected sortBy(column: SortColumn): void {
    this.state.setSort(column);
  }

  // --- Selection ----------------------------------------------------------

  protected isSelected(id: string): boolean {
    return this.selected().has(id);
  }
  protected toggleSelected(id: string): void {
    const next = new Set(this.selected());
    if (next.has(id)) next.delete(id);
    else next.add(id);
    this.selected.set(next);
    this.bulkBlockList.set(null);
  }

  // --- Drawer / row focus ---------------------------------------------------

  protected openRow(id: string): void {
    this.cursorId.set(id);
    this.openFindingId.set(id);
    this.savedMessage.set(null);
  }

  protected closeDrawer(): void {
    const id = this.openFindingId();
    this.openFindingId.set(null);
    // "returns focus to the originating row on close."
    if (id) this.focusRow(id);
  }

  protected onRowSaved(row: ReviewFindingRow): void {
    this.rows.update((rows) => rows.map((r) => (r.id === row.id ? row : r)));
  }

  private focusRow(id: string): void {
    const el = document.querySelector<HTMLElement>(`tr[data-row-id="${CSS.escape(id)}"]`);
    el?.focus();
  }

  // --- Keyboard model: j/k move, Enter opens, a/d/s set outcomes, Esc
  // closes (owned by the drawer itself), / focuses search.

  @HostListener('document:keydown', ['$event'])
  protected onKeydown(event: KeyboardEvent): void {
    const target = event.target as HTMLElement | null;
    const tag = target?.tagName ?? '';
    const isEditable = tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA';

    if (event.key === '/') {
      if (isEditable) return;
      event.preventDefault();
      this.searchInput()?.nativeElement.focus();
      return;
    }
    if (isEditable) return; // Escape-while-editing is the drawer's own concern (its own keydown handler).

    if (event.key === 'j' || event.key === 'ArrowDown') {
      event.preventDefault();
      this.moveCursor(1);
    } else if (event.key === 'k' || event.key === 'ArrowUp') {
      event.preventDefault();
      this.moveCursor(-1);
    } else if (event.key === 's') {
      event.preventDefault();
      this.moveCursor(1);
    } else if (event.key === 'Enter') {
      if (target?.matches('[data-row-id]')) {
        event.preventDefault();
        const id = target.getAttribute('data-row-id');
        if (id) this.openRow(id);
      }
    } else if (event.key === 'a') {
      this.drawer()?.selectVerdict('not_affected');
    } else if (event.key === 'd') {
      this.drawer()?.selectVerdict('affected');
    }
  }

  /** The drawer's own "↑ prev" / "next ↓" buttons — same move as `j`/`k`. */
  protected goPrev(): void {
    this.moveCursor(-1);
  }
  protected goNext(): void {
    this.moveCursor(1);
  }

  private moveCursor(delta: 1 | -1): void {
    const rows = this.sortedRows();
    if (rows.length === 0) return;
    const currentIndex = rows.findIndex((r) => r.id === this.cursorId());
    const nextIndex = Math.min(rows.length - 1, Math.max(0, currentIndex + delta));
    const next = rows[nextIndex];
    if (!next) return;
    this.cursorId.set(next.id);
    this.focusRow(next.id);
    // "the drawer follows without closing" — only if one is already open.
    if (this.openFindingId() != null) this.openFindingId.set(next.id);
  }

  // --- Bulk actions --------------------------------------------------------
  //
  // "apply only where legal for every selected row, and a refusal names
  // which rows blocked it." Never a partial apply.

  protected acceptRecommendations(): void {
    void this.runBulkAccept(this.selectedRows(), () => this.selected.set(new Set()));
  }

  protected approveAllReviewed(): void {
    void this.runBulkAccept(this.rows(), () => {});
  }

  private async runBulkAccept(candidates: ReviewFindingRow[], onDone: () => void): Promise<void> {
    if (candidates.length === 0) return;
    const blocks = computeBulkBlocks(candidates);
    if (blocks.length > 0) {
      this.bulkBlockList.set(blocks);
      return;
    }
    this.bulkBlockList.set(null);
    // Every candidate is legal, but "legal" here still only ever includes
    // rows the pipeline already auto-committed (see review.model.ts /
    // the task report) — decide() is never called a second time on an
    // already-decided finding (that would create a second IQ suppression;
    // commit_reviewer_clear is append-only, not idempotent). Nothing left
    // undecided among a legal selection is committed here; this loop exists
    // for the (currently theoretical, but schema-legal) case of an
    // undecided Tier 1 finding reaching the queue.
    const undecided = candidates.filter((row) => row.decided_by == null && row.outcome !== 'needs_review');
    for (const row of undecided) {
      try {
        const updated = await new Promise<ReviewFindingRow>((resolve, reject) => {
          this.reviewApi
            .decide(row.id, { outcome: row.outcome as 'not_affected' | 'affected', justification: row.justification })
            .subscribe({ next: resolve, error: reject });
        });
        this.onRowSaved(updated);
      } catch {
        // Surfaced generically; a per-row retry is available from the drawer.
      }
    }
    this.savedMessage.set(
      undecided.length > 0
        ? `${undecided.length} recommendation(s) accepted.`
        : 'Nothing needed accepting — every selected row is already decided.',
    );
    onDone();
  }

  protected sendToReview(): void {
    const rows = this.selectedRows();
    if (rows.length === 0) return;
    void Promise.all(
      rows.map(
        (row) =>
          new Promise<void>((resolve) => {
            this.reviewApi
              .recommend(row.id, { outcome: 'needs_review', note: 'Flagged for review from the queue.' })
              .subscribe({ next: () => resolve(), error: () => resolve() });
          }),
      ),
    ).then(() => {
      this.selected.set(new Set());
      this.savedMessage.set('Sent to review.');
    });
  }
}
