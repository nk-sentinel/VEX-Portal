import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';

import type { AssessmentSummary } from '../../core/api/models';
import { MyAssessments } from './my-assessments';

async function settle(fixture: ComponentFixture<MyAssessments>): Promise<void> {
  fixture.detectChanges();
  await fixture.whenStable();
  fixture.detectChanges();
}

function summary(overrides: Partial<AssessmentSummary> = {}): AssessmentSummary {
  return {
    id: 'ASM-2417',
    application_id: 'ledger-svc',
    report_id: 'r-1',
    state: 'completed',
    requester: 'j.doe',
    requester_note: 'context',
    finding_count: 9,
    outcome_counts: { not_affected: 7, affected: 1, needs_review: 0, risk_acceptance_required: 1 },
    created_at: new Date().toISOString(),
    submitted_at: new Date().toISOString(),
    expires_at: null,
    admission_failure: null,
    ...overrides,
  };
}

describe('MyAssessments', () => {
  let httpMock: HttpTestingController;
  let router: Router;
  let fixtures: ComponentFixture<MyAssessments>[];

  function setUp() {
    fixtures = [];
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])] });
    httpMock = TestBed.inject(HttpTestingController);
    router = TestBed.inject(Router);
    spyOn(router, 'navigate').and.resolveTo(true);
  }

  async function create(): Promise<ComponentFixture<MyAssessments>> {
    setUp();
    const fixture = TestBed.createComponent(MyAssessments);
    fixtures.push(fixture);
    await settle(fixture);
    return fixture;
  }

  afterEach(() => {
    fixtures.forEach((f) => f.destroy());
    httpMock.verify();
  });

  it('loading state: shows skeleton rows before the list resolves', () => {
    setUp();
    const fixture = TestBed.createComponent(MyAssessments);
    fixtures.push(fixture);
    fixture.detectChanges();
    expect(fixture.componentInstance['pageState']()).toBe('loading');
    httpMock.expectOne('/api/assessments').flush([]);
  });

  it('empty state: a first-time requester is told what an assessment needs, with a CTA', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/assessments').flush([]);
    await settle(fixture);

    expect(fixture.componentInstance['pageState']()).toBe('empty');
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('report URL');
    expect(text).toContain('Raise your first assessment');
  });

  it('error state: retry without losing state, no data blanked', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/assessments').flush({ detail: 'boom' }, { status: 500, statusText: 'Server Error' });
    await settle(fixture);
    expect(fixture.componentInstance['pageState']()).toBe('error');

    fixture.componentInstance['retry']();
    httpMock.expectOne('/api/assessments').flush([summary()]);
    await settle(fixture);
    expect(fixture.componentInstance['pageState']()).toBe('normal');
  });

  it('normal state: renders outcome counts for a completed assessment', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/assessments').flush([summary()]);
    await settle(fixture);

    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('7 not affected');
    expect(text).toContain('1 affected');
    expect(text).toContain('1 risk acceptance');
  });

  it('expiry countdown is prominent from 48 hours out — gets the "near" token, not the plain one', async () => {
    const fixture = await create();
    const in10h = new Date(Date.now() + 10 * 3_600_000).toISOString();
    httpMock.expectOne('/api/assessments').flush([summary({ expires_at: in10h })]);
    await settle(fixture);

    const html = (fixture.nativeElement as HTMLElement).innerHTML;
    expect(html).toContain('expiry--near');
    expect(html).toContain('expires in');
  });

  it('an assessment further than 48 hours out gets the plain expiry treatment, not the near one', async () => {
    const fixture = await create();
    const in6d = new Date(Date.now() + 6 * 24 * 3_600_000).toISOString();
    httpMock.expectOne('/api/assessments').flush([summary({ expires_at: in6d })]);
    await settle(fixture);

    const html = (fixture.nativeElement as HTMLElement).innerHTML;
    expect(html).not.toContain('expiry--near');
    expect(html).not.toContain('expiry--lapsed');
  });

  it('an expired assessment shows the lapsed token and a Raise reassessment action that prefills only application + note', async () => {
    const fixture = await create();
    const past = new Date(Date.now() - 3_600_000).toISOString();
    httpMock.expectOne('/api/assessments').flush([
      summary({ id: 'ASM-2410', application_id: 'batch-runner', state: 'expired', expires_at: past, requester_note: 'the old note' }),
    ]);
    await settle(fixture);

    expect((fixture.nativeElement as HTMLElement).innerHTML).toContain('expiry--lapsed');

    const btn = (fixture.nativeElement as HTMLElement).querySelector('button');
    // Find the "Raise reassessment" button specifically.
    const buttons = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('button'));
    const reassess = buttons.find((b) => b.textContent?.includes('Raise reassessment'));
    reassess?.dispatchEvent(new Event('click'));

    expect(router.navigate).toHaveBeenCalledWith(['/assessments/new'], {
      queryParams: { applicationId: 'batch-runner', note: 'the old note' },
    });
    void btn;
  });

  it('an admission-failed assessment shows the failure message and a Fix and resubmit action', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/assessments').flush([
      summary({
        id: 'ASM-2409',
        application_id: 'auth-gateway',
        state: 'admission_failed',
        finding_count: 0,
        outcome_counts: { not_affected: 0, affected: 0, needs_review: 0, risk_acceptance_required: 0 },
        report_id: 'r-9',
        admission_failure: { check: 'provenance', message: 'artifact did not match report' },
      }),
    ]);
    await settle(fixture);

    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('artifact did not match report');

    const buttons = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('button'));
    const fix = buttons.find((b) => b.textContent?.includes('Fix and resubmit'));
    fix?.dispatchEvent(new Event('click'));

    expect(router.navigate).toHaveBeenCalledWith(['/assessments/new'], {
      queryParams: { applicationId: 'auth-gateway', reportRef: 'r-9', note: 'context' },
    });
  });

  it('an analysing row renders without a fabricated fraction — no data source exists for one', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/assessments').flush([summary({ id: 'ASM-2418', state: 'analysing', finding_count: 12 })]);
    await settle(fixture);

    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('analysing');
    expect(text).not.toMatch(/\d+\/\d+/); // never invents an "8/12" style fraction
  });

  it('row click navigates to the Assessment Result screen', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/assessments').flush([summary({ id: 'ASM-2417' })]);
    await settle(fixture);

    (fixture.nativeElement as HTMLElement).querySelector('.row')?.dispatchEvent(new Event('click'));
    expect(router.navigate).toHaveBeenCalledWith(['/assessments', 'ASM-2417', 'result']);
  });

  it('filters by state and application, and can be cleared', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/assessments').flush([
      summary({ id: 'A1', application_id: 'payments-api', state: 'completed' }),
      summary({ id: 'A2', application_id: 'ledger-svc', state: 'expired', expires_at: new Date(Date.now() - 1000).toISOString() }),
    ]);
    await settle(fixture);

    fixture.componentInstance['stateFilter'].set('expired');
    await settle(fixture);
    expect(fixture.componentInstance['filteredRows']().map((r) => r.id)).toEqual(['A2']);

    fixture.componentInstance['clearFilters']();
    await settle(fixture);
    expect(fixture.componentInstance['filteredRows']().length).toBe(2);
  });
});
