import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap } from '@angular/router';

import type { AssessmentDetail } from '../../core/api/models';
import { AuthService } from '../../core/auth/auth.service';
import { AssessmentResult } from './assessment-result';

async function settle(fixture: ComponentFixture<AssessmentResult>): Promise<void> {
  fixture.detectChanges();
  await fixture.whenStable();
  fixture.detectChanges();
}

class FakeAuth {
  constructor(private readonly capabilities: readonly string[] = []) {}
  hasCapability(capability: string): boolean {
    return this.capabilities.includes(capability);
  }
}

function detail(overrides: Partial<AssessmentDetail> = {}): AssessmentDetail {
  return {
    id: 'ASM-2418',
    application_id: 'payments-api',
    report_id: 'r-1',
    state: 'completed',
    requester: 'j.doe',
    requester_note: 'note',
    commit_sha: '4a9f1c2',
    artifact_ref: 'payments-api:1.14.2',
    created_at: new Date().toISOString(),
    submitted_at: new Date().toISOString(),
    expires_at: null,
    admission_failure: null,
    provenance: { verdict: 'match', matched: 118, report_total: 118, ratio: 1.0, surplus_ratio: 0 },
    outcome_counts: { not_affected: 1, affected: 0, needs_review: 0, risk_acceptance_required: 1 },
    findings: [],
    ...overrides,
  };
}

describe('AssessmentResult', () => {
  let httpMock: HttpTestingController;
  let fixtures: ComponentFixture<AssessmentResult>[];

  function setUp(capabilities: readonly string[] = []) {
    fixtures = [];
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: AuthService, useValue: new FakeAuth(capabilities) },
        { provide: ActivatedRoute, useValue: { snapshot: { paramMap: convertToParamMap({ id: 'ASM-2418' }) } } },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  }

  async function create(capabilities: readonly string[] = []): Promise<ComponentFixture<AssessmentResult>> {
    setUp(capabilities);
    const fixture = TestBed.createComponent(AssessmentResult);
    fixtures.push(fixture);
    await settle(fixture);
    return fixture;
  }

  afterEach(() => {
    fixtures.forEach((f) => f.destroy());
    httpMock.verify();
  });

  it('loading state: shows a skeleton before the assessment resolves', () => {
    setUp();
    const fixture = TestBed.createComponent(AssessmentResult);
    fixtures.push(fixture);
    fixture.detectChanges();
    expect(fixture.componentInstance['pageState']()).toBe('loading');
    httpMock.expectOne('/api/assessments/ASM-2418').flush(detail());
  });

  it('error state: offers a retry and does not throw on a 404', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/assessments/ASM-2418').flush({ detail: 'assessment not found' }, { status: 404, statusText: 'Not Found' });
    await settle(fixture);

    expect(fixture.componentInstance['pageState']()).toBe('error');
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('assessment not found');
  });

  it('renders each finding\'s plain-language reason and evidence for a Not Affected verdict', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/assessments/ASM-2418').flush(
      detail({
        findings: [
          {
            id: 'f1',
            cve: 'CVE-2023-20860',
            purl: 'pkg:maven/org.springframework/spring-web@5.3.26',
            outcome: 'not_affected',
            reason: 'Not affected (Tier 1 evidence): the vulnerable code does not ship in this artifact.',
            tier: 1,
            justification: 'code_not_present',
            confidence: 'high',
            evidence_refs: ['rule:t1-class-absent:1.0:CVE-2023-20860'],
            decided_at: new Date().toISOString(),
          },
        ],
      }),
    );
    await settle(fixture);

    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('the vulnerable code does not ship');

    fixture.componentInstance['toggleEvidence']('f1');
    await settle(fixture);
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('rule:t1-class-absent:1.0:CVE-2023-20860');
  });

  it(
    'Risk Acceptance Required: shows the hand-off callout, never looks resolved, and gates the package ' +
      'download on real capability rather than a guaranteed-403 button',
    async () => {
      const fixture = await create([]); // no view_risk_acceptance
      httpMock.expectOne('/api/assessments/ASM-2418').flush(
        detail({
          findings: [
            {
              id: 'f2',
              cve: 'CVE-2019-17571',
              purl: 'pkg:maven/log4j/log4j@1.2.17',
              outcome: 'risk_acceptance_required',
              reason: 'No fix is available. This did not receive a determination. Take the evidence package to your risk manager.',
              tier: null,
              justification: null,
              confidence: null,
              evidence_refs: [],
              decided_at: null,
            },
          ],
        }),
      );
      await settle(fixture);

      const html = (fixture.nativeElement as HTMLElement).innerHTML;
      expect(html).toContain('callout--handoff');
      expect(html).toContain('No determination was made');
      expect(html).not.toContain('href='); // no dead download link rendered for this viewer
    },
  );

  it('shows the real download link when the viewer holds view_risk_acceptance', async () => {
    const fixture = await create(['view_risk_acceptance']);
    httpMock.expectOne('/api/assessments/ASM-2418').flush(
      detail({
        findings: [
          {
            id: 'f2',
            cve: 'CVE-2019-17571',
            purl: 'pkg:maven/log4j/log4j@1.2.17',
            outcome: 'risk_acceptance_required',
            reason: 'x',
            tier: null,
            justification: null,
            confidence: null,
            evidence_refs: [],
            decided_at: null,
          },
        ],
      }),
    );
    await settle(fixture);

    const link = (fixture.nativeElement as HTMLElement).querySelector('a[href]');
    expect(link?.getAttribute('href')).toBe('/api/risk-acceptance/f2/package');
  });

  it('an admission-failed assessment shows the failure, not an empty findings list', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/assessments/ASM-2418').flush(
      detail({ state: 'admission_failed', admission_failure: { check: 'artifact', message: 'artifact not found at that coordinate' } }),
    );
    await settle(fixture);

    expect((fixture.nativeElement as HTMLElement).textContent).toContain('artifact not found at that coordinate');
  });
});
