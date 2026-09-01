import { TestBed } from '@angular/core/testing';

import { ReviewQueueStateService } from './review-queue-state.service';

describe('ReviewQueueStateService', () => {
  beforeEach(() => {
    sessionStorage.removeItem('vex.review.filters');
    localStorage.removeItem('vex.review.grouping');
  });

  /** A fresh injector each call — simulates the singleton being instantiated anew (e.g. a hard reload), not sharing state across `service()` calls within one test the way a single TestBed instance would. */
  function service(): ReviewQueueStateService {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({});
    return TestBed.inject(ReviewQueueStateService);
  }

  it('defaults the unscoped queue to the "needs review" outcome filter', () => {
    expect(service().outcome()).toBe('needs_review');
  });

  it('toQuery() sends nothing for default/"all" filters', () => {
    const svc = service();
    expect(svc.toQuery()).toEqual({ state: ['needs_review'] });
    svc.setOutcome('all');
    expect(svc.toQuery()).toEqual({});
  });

  it('toQuery() reflects every active filter', () => {
    const svc = service();
    svc.setOutcome('affected');
    svc.setApplication('payments-api');
    svc.setSla('breaching');
    svc.setTier(2);
    svc.setSearch('  CVE-2024  ');
    expect(svc.toQuery()).toEqual({
      state: ['affected'],
      application_id: 'payments-api',
      sla: 'breaching',
      tier: '2',
      search: 'CVE-2024',
    });
  });

  it('isFiltered() is false only at the unscoped default', () => {
    const svc = service();
    expect(svc.isFiltered()).toBe(false);
    svc.setApplication('payments-api');
    expect(svc.isFiltered()).toBe(true);
  });

  it('clearFilters() restores the default outcome filter, not "all"', () => {
    const svc = service();
    svc.setOutcome('affected');
    svc.setApplication('payments-api');
    svc.setSearch('x');
    svc.clearFilters();
    expect(svc.outcome()).toBe('needs_review');
    expect(svc.application()).toBe('all');
    expect(svc.search()).toBe('');
  });

  it('setSort() toggles direction on a repeated column, resets to asc on a new one', () => {
    const svc = service();
    expect(svc.sortColumn()).toBe('sla');
    expect(svc.sortDirection()).toBe('asc');
    svc.setSort('sla');
    expect(svc.sortDirection()).toBe('desc');
    svc.setSort('age');
    expect(svc.sortColumn()).toBe('age');
    expect(svc.sortDirection()).toBe('asc');
  });

  it('grouping defaults to "none" and is persisted to localStorage across instances', () => {
    const first = service();
    expect(first.grouping()).toBe('none');
    first.setGrouping('assessment');
    expect(localStorage.getItem('vex.review.grouping')).toBe('assessment');

    // A fresh injector (simulating a full app reload) picks up the persisted value.
    const second = service();
    expect(second.grouping()).toBe('assessment');
  });

  it('filters survive a fresh injector — the mechanism behind "survive navigation": a providedIn:root service instance outlives a routed component being destroyed and recreated, and this proves the sessionStorage fallback holds even across a harder reset', () => {
    const first = service();
    first.setApplication('ledger-svc');
    first.setSla('urgent');
    first.setSearch('log4j');

    const second = service();
    expect(second.application()).toBe('ledger-svc');
    expect(second.sla()).toBe('urgent');
    expect(second.search()).toBe('log4j');
  });

  it('a corrupt sessionStorage value falls back to defaults rather than throwing', () => {
    sessionStorage.setItem('vex.review.filters', 'not json');
    expect(() => service()).not.toThrow();
    expect(service().outcome()).toBe('needs_review');
  });
});
