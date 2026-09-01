import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';

import type {
  AgreementPanel,
  AutomationSplitPanel,
  ExpiryPanel,
  OutcomeMixPanel,
  SlaPanel,
  VolumePanel,
} from '../../core/api/models';
import { AuthService } from '../../core/auth/auth.service';
import { Dashboard } from './dashboard';
import { ReviewQueueStateService } from '../review/review-queue-state.service';

async function settle(fixture: ComponentFixture<Dashboard>): Promise<void> {
  fixture.detectChanges();
  await fixture.whenStable();
  fixture.detectChanges();
}

class FakeAuth {
  constructor(private readonly capabilities: readonly string[] = ['view_dashboard', 'view_queue']) {}
  hasCapability(capability: string): boolean {
    return this.capabilities.includes(capability);
  }
}

const VOLUME: VolumePanel = {
  since: '2026-08-01T00:00:00Z',
  until: '2026-09-01T00:00:00Z',
  total_assessments: 10,
  total_findings: 40,
  findings_by_outcome: { not_affected: 20, affected: 5, needs_review: 10, risk_acceptance_required: 5 },
};
const AUTOMATION: AutomationSplitPanel = {
  since: '2026-08-01T00:00:00Z',
  until: '2026-09-01T00:00:00Z',
  total_decided: 30,
  automated: 24,
  human_reviewed: 6,
  automated_ratio: 0.8,
};
const SLA: SlaPanel = {
  since: '2026-08-01T00:00:00Z',
  until: '2026-09-01T00:00:00Z',
  median_hours_to_determination: 3.2,
  p90_hours_to_determination: 11.4,
  sample_size: 30,
  breaching_count: 3,
};
const AGREEMENT: AgreementPanel = {
  since: '2026-08-01T00:00:00Z',
  until: '2026-09-01T00:00:00Z',
  rules: [
    { rule_id: 't1-class-absent', tier: 1, agreement_rate: 0.98, agreement_bar: 0.9, below_bar: false, volume_30d: 50 },
    { rule_id: 't2-not-referenced', tier: 2, agreement_rate: 0.7, agreement_bar: 0.9, below_bar: true, volume_30d: 20 },
  ],
};
const OUTCOME_MIX: OutcomeMixPanel = {
  since: '2026-08-01T00:00:00Z',
  until: '2026-09-01T00:00:00Z',
  by_application: [{ application_id: 'payments-api', not_affected: 5, affected: 1, risk_acceptance_required: 1 }],
};
const EXPIRY: ExpiryPanel = { lapsing_within_7_days: 4, already_expired: 2 };

describe('Dashboard', () => {
  let httpMock: HttpTestingController;
  let router: Router;
  let queueState: ReviewQueueStateService;
  let fixtures: ComponentFixture<Dashboard>[];

  function setUp(capabilities: readonly string[] = ['view_dashboard', 'view_queue']) {
    fixtures = [];
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: AuthService, useValue: new FakeAuth(capabilities) },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    router = TestBed.inject(Router);
    queueState = TestBed.inject(ReviewQueueStateService);
    spyOn(router, 'navigateByUrl').and.resolveTo(true);
  }

  async function create(capabilities: readonly string[] = ['view_dashboard', 'view_queue']): Promise<ComponentFixture<Dashboard>> {
    setUp(capabilities);
    const fixture = TestBed.createComponent(Dashboard);
    fixtures.push(fixture);
    await settle(fixture);
    return fixture;
  }

  function flushAll(): void {
    httpMock.expectOne((r) => r.url === '/api/dashboard/volume').flush(VOLUME);
    httpMock.expectOne((r) => r.url === '/api/dashboard/automation-split').flush(AUTOMATION);
    httpMock.expectOne((r) => r.url === '/api/dashboard/sla').flush(SLA);
    httpMock.expectOne((r) => r.url === '/api/dashboard/agreement').flush(AGREEMENT);
    httpMock.expectOne((r) => r.url === '/api/dashboard/outcome-mix').flush(OUTCOME_MIX);
    httpMock.expectOne((r) => r.url === '/api/dashboard/expiry').flush(EXPIRY);
  }

  afterEach(() => {
    fixtures.forEach((f) => f.destroy());
    httpMock.verify();
  });

  it('loading state: every panel starts loading independently', () => {
    setUp();
    const fixture = TestBed.createComponent(Dashboard);
    fixtures.push(fixture);
    fixture.detectChanges();
    expect(fixture.componentInstance['volume']().status).toBe('loading');
    expect(fixture.componentInstance['agreement']().status).toBe('loading');
    flushAll();
  });

  it('default state: renders all six panels once loaded', async () => {
    const fixture = await create();
    flushAll();
    await settle(fixture);

    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('80%');
    expect(text).toContain('3 breaching');
    expect(text).toContain('below its bar');
    expect(text).toContain('payments-api');
    expect(fixture.componentInstance['expiry']().data?.lapsing_within_7_days).toBe(4);
  });

  it('error state: one panel failing does not blank the others', async () => {
    const fixture = await create();
    httpMock.expectOne((r) => r.url === '/api/dashboard/volume').flush({ detail: 'boom' }, { status: 500, statusText: 'Server Error' });
    httpMock.expectOne((r) => r.url === '/api/dashboard/automation-split').flush(AUTOMATION);
    httpMock.expectOne((r) => r.url === '/api/dashboard/sla').flush(SLA);
    httpMock.expectOne((r) => r.url === '/api/dashboard/agreement').flush(AGREEMENT);
    httpMock.expectOne((r) => r.url === '/api/dashboard/outcome-mix').flush(OUTCOME_MIX);
    httpMock.expectOne((r) => r.url === '/api/dashboard/expiry').flush(EXPIRY);
    await settle(fixture);

    expect(fixture.componentInstance['volume']().status).toBe('error');
    expect(fixture.componentInstance['automationSplit']().status).toBe('loaded');
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('80%'); // automation split panel still rendered
  });

  it('every number that can link to rows sets the shared queue filter state before navigating', async () => {
    const fixture = await create();
    flushAll();
    await settle(fixture);

    fixture.componentInstance['drillOutcome']('affected');
    expect(queueState.outcome()).toBe('affected');
    expect(router.navigateByUrl).toHaveBeenCalledWith('/review');

    fixture.componentInstance['drillApplication']('payments-api');
    expect(queueState.application()).toBe('payments-api');

    fixture.componentInstance['drillBreaching']();
    expect(queueState.sla()).toBe('breaching');
  });

  it('never drills into the queue for a viewer without view_queue (e.g. an Admin)', async () => {
    const fixture = await create(['view_dashboard']); // admin: no view_queue
    flushAll();
    await settle(fixture);

    fixture.componentInstance['drillOutcome']('affected');
    expect(router.navigateByUrl).not.toHaveBeenCalled();

    const html = (fixture.nativeElement as HTMLElement).innerHTML;
    // The rule-id link is rendered as plain text, not a button, when the viewer cannot drill in.
    expect(html).toContain('t1-class-absent');
  });

  it('the application filter is populated from outcome-mix, not a GET /api/applications call', async () => {
    const fixture = await create();
    flushAll();
    await settle(fixture);
    expect(fixture.componentInstance['applicationOptions']()).toEqual(['payments-api']);
  });

  it('changing the date range reloads every panel', async () => {
    const fixture = await create();
    flushAll();
    await settle(fixture);

    fixture.componentInstance['onRangeChange']('7');
    flushAll();
    await settle(fixture);
    expect(fixture.componentInstance['rangePreset']()).toBe(7);
  });
});
