import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { ActivatedRoute, convertToParamMap, type ParamMap } from '@angular/router';
import { BehaviorSubject } from 'rxjs';

import type { ReviewFindingDetail, ReviewFindingRow } from '../../core/api/models';
import { AuthService } from '../../core/auth/auth.service';
import { ReviewQueue } from './review-queue';
import { ReviewQueueStateService } from './review-queue-state.service';

/**
 * See the identical helper in `evidence-drawer.spec.ts`. Two things need
 * waiting on here, not one `detectChanges()`:
 *  1. The constructor `effect()` that drives `reload()`/`loadAssessmentHeader()`
 *     is scheduled, not synchronous — `whenStable()` is what actually waits
 *     for it (and, transitively, its HTTP call) to register with
 *     `HttpTestingController`.
 *  2. Once an async chain resolves (e.g. `reload()`'s promise, after a test
 *     flushes the request `whenStable()` waited out), writing to a signal
 *     does not itself repaint the DOM — OnPush change detection needs a
 *     further `detectChanges()` call to actually flush that new state into
 *     the rendered template, which is why this calls it both before AND
 *     after the stability wait.
 */
async function settle(fixture: ComponentFixture<unknown>): Promise<void> {
  fixture.detectChanges();
  await fixture.whenStable();
  fixture.detectChanges();
}

/** Minimal `ReviewFindingDetail` for tests that only need the Evidence
 * Drawer to mount and its own fetch to resolve — never render assertions. */
function drawerDetail(id: string): ReviewFindingDetail {
  return {
    id,
    assessment_id: 'asm-1',
    application_id: 'payments-api',
    cve: 'CVE-2024-0001',
    purl: 'pkg:maven/x/y@1.0',
    threat_level: null,
    outcome: 'needs_review',
    recommendation: {
      outcome: 'needs_review',
      reason: 'x',
      tier: null,
      justification: null,
      confidence: null,
      requires_second_confirmation: false,
    },
    rule_trace: [],
    escalation: { hard_blockers: [], note: 'not a basis for clearing' },
    ai_verdict: null,
    missing_evidence: [],
    determination: null,
  };
}

function row(overrides: Partial<ReviewFindingRow> = {}): ReviewFindingRow {
  return {
    id: 'f1',
    assessment_id: 'asm-1',
    application_id: 'payments-api',
    cve: 'CVE-2024-0001',
    purl: 'pkg:maven/x/y@1.0',
    outcome: 'needs_review',
    recommended_outcome: 'needs_review',
    tier: null,
    justification: null,
    confidence: null,
    sla_band: 'ok',
    sla_hours_remaining: 10,
    age_hours: 2,
    requester: 'requester1',
    decided_by: null,
    decided_at: null,
    ...overrides,
  };
}

class FakeAuth {
  private readonly _username = signal('reviewer1');
  readonly username = this._username.asReadonly();
  hasCapability(capability: string): boolean {
    return capability === 'view_queue' || capability === 'recommend_determination' || capability === 'commit_determination';
  }
}

class FakeActivatedRoute {
  private readonly subject = new BehaviorSubject<ParamMap>(convertToParamMap({}));
  readonly paramMap = this.subject.asObservable();
  get snapshot(): { paramMap: ParamMap } {
    return { paramMap: this.subject.value };
  }
  setId(id: string | null): void {
    this.subject.next(convertToParamMap(id ? { id } : {}));
  }
}

describe('ReviewQueue', () => {
  let httpMock: HttpTestingController;
  let fakeRoute: FakeActivatedRoute;
  // Every fixture `create()` produces, destroyed in `afterEach` — a
  // constructor `effect()` (this component's filter-driven reload) stays
  // alive and keeps firing against its own DI-provided services for as
  // long as its fixture is never destroyed, which otherwise leaks a live
  // reload effect from one test into the next test's shared browser page
  // and Jasmine run (every Karma spec file executes in one page load) —
  // manifesting as a mysterious *extra* `GET /api/review/findings` still
  // pending in a later, unrelated test's `httpMock.verify()`.
  let fixtures: ComponentFixture<ReviewQueue>[];

  beforeEach(() => {
    sessionStorage.removeItem('vex.review.filters');
    localStorage.removeItem('vex.review.grouping');
    fakeRoute = new FakeActivatedRoute();
    fixtures = [];
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: AuthService, useValue: new FakeAuth() },
        { provide: ActivatedRoute, useValue: fakeRoute },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    fixtures.forEach((f) => f.destroy());
    httpMock.verify();
  });

  async function create(): Promise<ComponentFixture<ReviewQueue>> {
    const fixture = TestBed.createComponent(ReviewQueue);
    fixtures.push(fixture);
    await settle(fixture);
    return fixture;
  }

  function flushFindings(rows: ReviewFindingRow[]): void {
    const req = httpMock.expectOne((r) => r.url === '/api/review/findings');
    req.flush(rows);
  }

  describe('filters', () => {
    it('survive a drawer open/close round trip', async () => {
      const fixture = await create();
      flushFindings([row({ id: 'a' })]);
      await settle(fixture);

      const state = TestBed.inject(ReviewQueueStateService);
      state.setApplication('ledger-svc');
      await settle(fixture); // lets the filter-driven effect actually issue the new request
      httpMock.expectOne((r) => r.url === '/api/review/findings').flush([]);
      await settle(fixture);

      fixture.componentInstance['openRow']('a');
      await settle(fixture);
      httpMock.expectOne('/api/review/findings/a').flush(drawerDetail('a')); // the drawer's own fetch
      await settle(fixture);
      fixture.componentInstance['closeDrawer']();
      await settle(fixture);

      expect(state.application()).toBe('ledger-svc');
    });

    it('survive the routed component being destroyed and recreated (navigation away and back) — the singleton service, not the component, owns this state', async () => {
      const fixture = await create();
      flushFindings([]);
      await settle(fixture);

      const state = TestBed.inject(ReviewQueueStateService);
      state.setSla('breaching');
      state.setSearch('log4j');

      fixture.destroy();

      const second = TestBed.createComponent(ReviewQueue);
      fixtures.push(second);
      await settle(second);
      httpMock.expectOne((r) => r.url === '/api/review/findings' && r.params.get('sla') === 'breaching' && r.params.get('search') === 'log4j');
      await settle(second);

      expect(second.componentInstance['state'].sla()).toBe('breaching');
      expect(second.componentInstance['state'].search()).toBe('log4j');
    });
  });

  describe('keyboard model', () => {
    it('j/k move the cursor; the drawer follows only once it is already open', async () => {
      const fixture = await create();
      const rows = [row({ id: 'a' }), row({ id: 'b' }), row({ id: 'c' })];
      flushFindings(rows);
      await settle(fixture);

      const component = fixture.componentInstance;
      expect(component['cursorId']()).toBe('a'); // first row is the initial roving-tabindex target

      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'j' }));
      expect(component['cursorId']()).toBe('b');
      expect(component['openFindingId']()).toBeNull(); // moving the cursor alone never opens the drawer

      component['openRow']('b');
      expect(component['openFindingId']()).toBe('b');

      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'j' }));
      expect(component['cursorId']()).toBe('c');
      expect(component['openFindingId']()).withContext('the drawer follows without closing').toBe('c');

      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'k' }));
      expect(component['cursorId']()).toBe('b');
      expect(component['openFindingId']()).toBe('b');
    });

    it('ignores j/k/a/d while an editable field (e.g. the search box) has focus', async () => {
      const fixture = await create();
      flushFindings([row({ id: 'a' }), row({ id: 'b' })]);
      await settle(fixture);
      const component = fixture.componentInstance;

      const input = document.createElement('input');
      document.body.appendChild(input);
      input.focus();
      // Dispatched on the input itself (bubbles to document, so
      // `event.target` is the input) — simulates a real keypress while
      // typing, not a synthetic one with no target.
      input.dispatchEvent(new KeyboardEvent('keydown', { key: 'j', bubbles: true, cancelable: true }));

      expect(component['cursorId']()).toBe('a');
      input.remove();
    });

    it('returns focus to the originating row when the drawer closes', async () => {
      const fixture = await create();
      document.body.appendChild(fixture.nativeElement);
      flushFindings([row({ id: 'a' }), row({ id: 'b' })]);
      await settle(fixture);

      const component = fixture.componentInstance;
      component['openRow']('b');
      await settle(fixture);
      httpMock.expectOne('/api/review/findings/b').flush(drawerDetail('b')); // the drawer's own fetch
      await settle(fixture);
      component['closeDrawer']();
      await settle(fixture);

      const rowEl = fixture.nativeElement.querySelector('tr[data-row-id="b"]');
      expect(document.activeElement).toBe(rowEl);
      fixture.nativeElement.remove();
    });
  });

  describe('bulk actions', () => {
    it('Accept recommendations refuses the whole selection and names every blocking row, applying nothing', async () => {
      const fixture = await create();
      const rows = [
        row({ id: 'a', cve: 'CVE-A', outcome: 'not_affected', tier: 1, decided_by: 'system:pipeline' }),
        row({ id: 'b', cve: 'CVE-B', outcome: 'needs_review' }),
        row({ id: 'c', cve: 'CVE-C', outcome: 'not_affected', tier: 2, decided_by: 'approver1' }),
      ];
      flushFindings(rows);
      await settle(fixture);

      const component = fixture.componentInstance;
      component['toggleSelected']('a');
      component['toggleSelected']('b');
      component['toggleSelected']('c');
      component['acceptRecommendations']();
      await settle(fixture);

      const blocks = component['bulkBlockList']();
      expect(blocks).not.toBeNull();
      expect(blocks!.map((b) => b.cve)).toEqual(['CVE-B', 'CVE-C']);
      // Refused outright — no decide() call for any row, selection untouched.
      httpMock.expectNone((r) => r.url.includes('/decide'));
      expect(component['selected']().size).toBe(3);
    });

    it('a fully legal selection is accepted with no refusal callout', async () => {
      const fixture = await create();
      const rows = [row({ id: 'a', cve: 'CVE-A', outcome: 'affected', decided_by: 'system:pipeline' })];
      flushFindings(rows);
      await settle(fixture);

      const component = fixture.componentInstance;
      component['toggleSelected']('a');
      component['acceptRecommendations']();
      await settle(fixture);

      expect(component['bulkBlockList']()).toBeNull();
      httpMock.expectNone((r) => r.url.includes('/decide')); // already decided — nothing left to commit
    });
  });

  describe('states', () => {
    it('an empty, unfiltered queue reads as good news, not an error', async () => {
      const fixture = await create();
      flushFindings([]);
      await settle(fixture);
      const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
      expect(text).toContain('Nothing needs review.');
    });

    it('an empty FILTERED queue is distinguished, with an offer to clear filters', async () => {
      const fixture = await create();
      flushFindings([row({ id: 'a' })]); // the default-filtered load — must be flushed before changing filters
      await settle(fixture);

      const state = TestBed.inject(ReviewQueueStateService);
      state.setApplication('some-other-app');
      await settle(fixture); // lets the filter-driven effect actually issue the new request
      httpMock.expectOne((r) => r.url === '/api/review/findings').flush([]);
      await settle(fixture);

      const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
      expect(text).not.toContain('Nothing needs review.');
      expect(text).toContain('No findings match these filters.');
      expect(fixture.nativeElement.querySelector('button')?.textContent).toBeDefined();
    });

    it('a refresh failure keeps the existing rows visible and shows a stale-data banner with the last-updated time, never blanking the table', async () => {
      const fixture = await create();
      flushFindings([row({ id: 'a', cve: 'CVE-STAYS' })]);
      await settle(fixture);

      const state = TestBed.inject(ReviewQueueStateService);
      state.setSearch('trigger-a-reload');
      await settle(fixture); // lets the filter-driven effect actually issue the new request
      httpMock.expectOne((r) => r.url === '/api/review/findings').flush({ detail: 'IQ unreachable' }, { status: 502, statusText: 'Bad Gateway' });
      await settle(fixture);

      const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
      expect(text).toContain('CVE-STAYS'); // table not blanked
      expect(text).toContain('Could not refresh');
      expect(fixture.componentInstance['rows']().length).toBe(1);
    });

    it('an initial load failure (no prior data) shows the full error state, not a stale-table banner', async () => {
      const fixture = await create();
      httpMock.expectOne((r) => r.url === '/api/review/findings').flush({ detail: 'IQ unreachable' }, { status: 502, statusText: 'Bad Gateway' });
      await settle(fixture);
      expect(fixture.componentInstance['pageState']()).toBe('error');
    });
  });

  
describe('scoped mode ([6] Assessment Detail)', () => {
    it('scopes the query to the assessment id and omits the queue-only filter bar', async () => {
      fakeRoute.setId('asm-1');
      const fixture = await create();
      const req = httpMock.expectOne((r) => r.url === '/api/review/findings');
      expect(req.request.params.get('assessment_id')).toBe('asm-1');
      req.flush([row({ id: 'a', assessment_id: 'asm-1' })]);
      httpMock.expectOne('/api/assessments/asm-1').flush({
        id: 'asm-1',
        application_id: 'payments-api',
        report_id: 'report-1',
        state: 'needs_review',
        requester: 'requester1',
        requester_note: null,
        commit_sha: null,
        artifact_ref: null,
        created_at: new Date().toISOString(),
        submitted_at: new Date().toISOString(),
        expires_at: null,
        admission_failure: null,
        provenance: null,
        outcome_counts: { not_affected: 0, affected: 0, needs_review: 1, risk_acceptance_required: 0 },
        findings: [],
      });
      await settle(fixture);

      expect(fixture.nativeElement.querySelector('.field-label')).toBeNull(); // no filter chips in scoped mode
      expect(fixture.componentInstance['scoped']()).toBe(true);
    });
  });
});
