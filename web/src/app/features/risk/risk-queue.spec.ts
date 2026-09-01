import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import type { RiskAcceptanceRow } from '../../core/api/models';
import { AuthService } from '../../core/auth/auth.service';
import { RiskQueue } from './risk-queue';

async function settle(fixture: ComponentFixture<RiskQueue>): Promise<void> {
  fixture.detectChanges();
  await fixture.whenStable();
  fixture.detectChanges();
}

class FakeAuth {
  constructor(private readonly capabilities: readonly string[] = ['view_risk_acceptance', 'manage_risk_acceptance']) {}
  hasCapability(capability: string): boolean {
    return this.capabilities.includes(capability);
  }
}

function row(overrides: Partial<RiskAcceptanceRow> = {}): RiskAcceptanceRow {
  return {
    finding_id: 'f1',
    assessment_id: 'asm-1',
    application_id: 'batch-runner',
    cve: 'CVE-2019-17571',
    purl: 'pkg:maven/log4j/log4j@1.2.17',
    reason: 'No fix is available. This did not receive a determination.',
    escalation: { epss: 0.02, kev: false, cvss_base_score: 9.8, cvss_vector: null, fix_available: false, hard_blockers: [], note: 'not a basis for clearing' },
    affected_applications_count: 2,
    age_hours: 96,
    status: 'awaiting_hand_off',
    status_updated_by: null,
    status_updated_at: null,
    ...overrides,
  };
}

describe('RiskQueue', () => {
  let httpMock: HttpTestingController;
  let fixtures: ComponentFixture<RiskQueue>[];

  function setUp(capabilities: readonly string[] = ['view_risk_acceptance', 'manage_risk_acceptance']) {
    fixtures = [];
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), { provide: AuthService, useValue: new FakeAuth(capabilities) }],
    });
    httpMock = TestBed.inject(HttpTestingController);
  }

  async function create(capabilities: readonly string[] = ['view_risk_acceptance', 'manage_risk_acceptance']): Promise<ComponentFixture<RiskQueue>> {
    setUp(capabilities);
    const fixture = TestBed.createComponent(RiskQueue);
    fixtures.push(fixture);
    await settle(fixture);
    return fixture;
  }

  afterEach(() => {
    fixtures.forEach((f) => f.destroy());
    httpMock.verify();
  });

  it('loading state: shows skeleton rows', () => {
    setUp();
    const fixture = TestBed.createComponent(RiskQueue);
    fixtures.push(fixture);
    fixture.detectChanges();
    expect(fixture.componentInstance['pageState']()).toBe('loading');
    httpMock.expectOne('/api/risk-acceptance').flush([]);
  });

  it('empty state: nothing waiting on a risk decision', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/risk-acceptance').flush([]);
    await settle(fixture);
    expect(fixture.componentInstance['pageState']()).toBe('empty');
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Nothing is waiting');
  });

  it('error state: offers a retry', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/risk-acceptance').flush({ detail: 'boom' }, { status: 500, statusText: 'Server Error' });
    await settle(fixture);
    expect(fixture.componentInstance['pageState']()).toBe('error');

    fixture.componentInstance['retry']();
    httpMock.expectOne('/api/risk-acceptance').flush([row()]);
    await settle(fixture);
    expect(fixture.componentInstance['pageState']()).toBe('normal');
  });

  it('normal state: states plainly this is a hand-off, not a determination', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/risk-acceptance').flush([row()]);
    await settle(fixture);

    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('not determinations');
    expect(text).toContain('does not enforce the outcome');
  });

  it('a risk manager can change the hand-off status', async () => {
    const fixture = await create(['view_risk_acceptance', 'manage_risk_acceptance']);
    httpMock.expectOne('/api/risk-acceptance').flush([row()]);
    await settle(fixture);

    const updatePromise = fixture.componentInstance['updateStatus'](row(), 'with_risk_manager');
    const req = httpMock.expectOne('/api/risk-acceptance/f1/status');
    expect(req.request.body).toEqual({ status: 'with_risk_manager' });
    req.flush(row({ status: 'with_risk_manager' }));
    await updatePromise;

    expect(fixture.componentInstance['rows']()[0].status).toBe('with_risk_manager');
  });

  it('an auditor (view only) sees the status as plain text, not an editable select', async () => {
    const fixture = await create(['view_risk_acceptance']); // no manage_risk_acceptance
    httpMock.expectOne('/api/risk-acceptance').flush([row()]);
    await settle(fixture);

    expect(fixture.componentInstance['canManage']()).toBeFalse();
    const select = (fixture.nativeElement as HTMLElement).querySelector('select[aria-label*="hand-off"]');
    expect(select).toBeNull();
  });

  it('the package download is a real, working link for every viewer of this screen', async () => {
    const fixture = await create(['view_risk_acceptance']);
    httpMock.expectOne('/api/risk-acceptance').flush([row()]);
    await settle(fixture);

    const link = (fixture.nativeElement as HTMLElement).querySelector('a.btn--handoff');
    expect(link?.getAttribute('href')).toBe('/api/risk-acceptance/f1/package');
  });

  it('the row opens the Evidence Drawer only for a viewer holding view_queue (an Auditor, not a Risk Manager)', async () => {
    const fixture = await create(['view_risk_acceptance', 'manage_risk_acceptance']); // risk_manager: no view_queue
    httpMock.expectOne('/api/risk-acceptance').flush([row()]);
    await settle(fixture);

    fixture.componentInstance['openRow']('f1');
    expect(fixture.componentInstance['openFindingId']()).toBeNull();

    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('cannot open the evidence drawer');
  });

  it('an auditor with view_queue can open the drawer', async () => {
    const fixture = await create(['view_risk_acceptance', 'view_queue']);
    httpMock.expectOne('/api/risk-acceptance').flush([row()]);
    await settle(fixture);

    fixture.componentInstance['openRow']('f1');
    await settle(fixture);
    expect(fixture.componentInstance['openFindingId']()).toBe('f1');
    httpMock.expectOne('/api/review/findings/f1').flush({
      id: 'f1',
      assessment_id: 'asm-1',
      application_id: 'batch-runner',
      cve: 'CVE-2019-17571',
      purl: 'pkg:maven/log4j/log4j@1.2.17',
      threat_level: null,
      outcome: 'risk_acceptance_required',
      recommendation: { outcome: 'risk_acceptance_required', reason: 'x', tier: null, justification: null, confidence: null, requires_second_confirmation: false },
      rule_trace: [],
      escalation: { hard_blockers: [], note: 'not a basis for clearing' },
      ai_verdict: null,
      missing_evidence: [],
      determination: null,
    });
  });
});
