import { Injectable, computed, signal } from '@angular/core';

import type { EvidenceTier, ReviewFindingsQuery, SlaBand } from '../../core/api/models';
import type { SortColumn, SortDirection } from './review.model';

export type OutcomeFilter = 'all' | 'not_affected' | 'affected' | 'needs_review' | 'risk_acceptance_required';
export type TierFilter = 'all' | EvidenceTier;
export type SlaFilter = 'all' | SlaBand;
export type Grouping = 'none' | 'assessment';

interface PersistedFilters {
  outcome: OutcomeFilter;
  application: string;
  sla: SlaFilter;
  tier: TierFilter;
  search: string;
  sortColumn: SortColumn;
  sortDirection: SortDirection;
}

const FILTERS_KEY = 'vex.review.filters';
const GROUPING_KEY = 'vex.review.grouping';

/** The unscoped queue's own default — "the queue's own 'needs review' default filter chip" (`app/api/review.py`'s module docstring). */
const DEFAULT_FILTERS: PersistedFilters = {
  outcome: 'needs_review',
  application: 'all',
  sla: 'all',
  tier: 'all',
  search: '',
  sortColumn: 'sla',
  sortDirection: 'asc',
};

function loadFilters(): PersistedFilters {
  try {
    const raw = sessionStorage.getItem(FILTERS_KEY);
    if (!raw) return { ...DEFAULT_FILTERS };
    const parsed = JSON.parse(raw) as Partial<PersistedFilters>;
    return { ...DEFAULT_FILTERS, ...parsed };
  } catch {
    return { ...DEFAULT_FILTERS };
  }
}

function loadGrouping(): Grouping {
  try {
    const raw = localStorage.getItem(GROUPING_KEY);
    return raw === 'assessment' ? 'assessment' : 'none';
  } catch {
    return 'none';
  }
}

/**
 * The Review Queue's filter/sort/grouping state — deliberately a
 * `providedIn: 'root'` singleton, not component state.
 *
 * **Why this exists at all**: `docs/design/ui-spec.md`'s "Filters persist
 * across drawer open/close and across navigation. A reviewer who loses
 * their filter set on every drill-in will stop using the filters." Opening
 * the Evidence Drawer never navigates (`review-queue.ts` just toggles which
 * finding id is open, same route, same component instance) so filters
 * trivially survive that round trip regardless of where they live; what
 * actually needs a home outside the routed component is surviving a real
 * navigation away (Dashboard, Risk Acceptance, back to `/review`) and back
 * — a `providedIn: 'root'` service's state outlives the component's
 * destroy/recreate cycle for the lifetime of the app, which `ReviewQueue`
 * relies on instead of re-deriving defaults on every construction.
 *
 * Also mirrored into `sessionStorage` (filters) / `localStorage` (grouping,
 * "the choice persisted per user" per ui-spec) so a hard reload mid-session
 * does not silently reset a reviewer's working set either — `sessionStorage`
 * rather than `localStorage` for the filters themselves so a different
 * reviewer's next browser session does not inherit a stale filter set on a
 * shared machine.
 */
@Injectable({ providedIn: 'root' })
export class ReviewQueueStateService {
  private readonly _outcome = signal<OutcomeFilter>(loadFilters().outcome);
  private readonly _application = signal<string>(loadFilters().application);
  private readonly _sla = signal<SlaFilter>(loadFilters().sla);
  private readonly _tier = signal<TierFilter>(loadFilters().tier);
  private readonly _search = signal<string>(loadFilters().search);
  private readonly _sortColumn = signal<SortColumn>(loadFilters().sortColumn);
  private readonly _sortDirection = signal<SortDirection>(loadFilters().sortDirection);
  private readonly _grouping = signal<Grouping>(loadGrouping());

  readonly outcome = this._outcome.asReadonly();
  readonly application = this._application.asReadonly();
  readonly sla = this._sla.asReadonly();
  readonly tier = this._tier.asReadonly();
  readonly search = this._search.asReadonly();
  readonly sortColumn = this._sortColumn.asReadonly();
  readonly sortDirection = this._sortDirection.asReadonly();
  readonly grouping = this._grouping.asReadonly();

  readonly isFiltered = computed(
    () =>
      this._outcome() !== DEFAULT_FILTERS.outcome ||
      this._application() !== 'all' ||
      this._sla() !== 'all' ||
      this._tier() !== 'all' ||
      this._search().trim() !== '',
  );

  setOutcome(value: OutcomeFilter): void {
    this._outcome.set(value);
    this.persist();
  }
  setApplication(value: string): void {
    this._application.set(value);
    this.persist();
  }
  setSla(value: SlaFilter): void {
    this._sla.set(value);
    this.persist();
  }
  setTier(value: TierFilter): void {
    this._tier.set(value);
    this.persist();
  }
  setSearch(value: string): void {
    this._search.set(value);
    this.persist();
  }
  setSort(column: SortColumn): void {
    if (this._sortColumn() === column) {
      this._sortDirection.set(this._sortDirection() === 'asc' ? 'desc' : 'asc');
    } else {
      this._sortColumn.set(column);
      this._sortDirection.set('asc');
    }
    this.persist();
  }
  setGrouping(value: Grouping): void {
    this._grouping.set(value);
    try {
      localStorage.setItem(GROUPING_KEY, value);
    } catch {
      // Private-browsing / storage-disabled — grouping just resets next load, not fatal.
    }
  }

  /** Restores every filter to the unscoped queue's own default (never affects grouping/sort, matching the mockup's own `clearFilters`). */
  clearFilters(): void {
    this._outcome.set(DEFAULT_FILTERS.outcome);
    this._application.set(DEFAULT_FILTERS.application);
    this._sla.set(DEFAULT_FILTERS.sla);
    this._tier.set(DEFAULT_FILTERS.tier);
    this._search.set('');
    this.persist();
  }

  /** The current filters as `GET /api/review/findings` query params — `assessment_id` is layered on separately by the scoped (Assessment Detail) caller, never stored here. */
  toQuery(): ReviewFindingsQuery {
    const query: ReviewFindingsQuery = {};
    if (this._outcome() !== 'all') query.state = [this._outcome()];
    if (this._application() !== 'all') query.application_id = this._application();
    if (this._sla() !== 'all') query.sla = this._sla() as SlaBand;
    if (this._tier() !== 'all') query.tier = String(this._tier());
    if (this._search().trim() !== '') query.search = this._search().trim();
    return query;
  }

  private persist(): void {
    try {
      const value: PersistedFilters = {
        outcome: this._outcome(),
        application: this._application(),
        sla: this._sla(),
        tier: this._tier(),
        search: this._search(),
        sortColumn: this._sortColumn(),
        sortDirection: this._sortDirection(),
      };
      sessionStorage.setItem(FILTERS_KEY, JSON.stringify(value));
    } catch {
      // Private-browsing / storage-disabled — filters just don't survive a hard reload, not fatal.
    }
  }
}
