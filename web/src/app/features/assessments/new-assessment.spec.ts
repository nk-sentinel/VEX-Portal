import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router, convertToParamMap } from '@angular/router';

import type { ApplicationOut } from '../../core/api/models';
import { NewAssessment } from './new-assessment';

async function settle(fixture: ComponentFixture<NewAssessment>): Promise<void> {
  fixture.detectChanges();
  await fixture.whenStable();
  fixture.detectChanges();
}

const APPS: ApplicationOut[] = [
  { id: 'payments-api', name: 'payments-api' },
  { id: 'ledger-svc', name: 'ledger-svc' },
];

describe('NewAssessment', () => {
  let httpMock: HttpTestingController;
  let router: Router;
  let fixtures: ComponentFixture<NewAssessment>[];

  function setUp(queryParams: Record<string, string> = {}) {
    fixtures = [];
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ActivatedRoute, useValue: { snapshot: { queryParamMap: convertToParamMap(queryParams) } } },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    router = TestBed.inject(Router);
    spyOn(router, 'navigate').and.resolveTo(true);
  }

  async function create(queryParams: Record<string, string> = {}): Promise<ComponentFixture<NewAssessment>> {
    setUp(queryParams);
    const fixture = TestBed.createComponent(NewAssessment);
    fixtures.push(fixture);
    await settle(fixture);
    return fixture;
  }

  afterEach(() => {
    fixtures.forEach((f) => f.destroy());
    httpMock.verify();
  });

  function fillRequiredFields(fixture: ComponentFixture<NewAssessment>): void {
    const c = fixture.componentInstance;
    c['applicationId'].set('payments-api');
    c['reportRef'].set('38ef4d1f');
    c['artifactCoordinates'].set('artifactory.example.com/payments-api:1.14.2');
    c['requesterNote'].set('upgrade blocked until Q4');
  }

  it('loading state: shows a skeleton before applications resolve', () => {
    setUp();
    const fixture = TestBed.createComponent(NewAssessment);
    fixtures.push(fixture);
    fixture.detectChanges();
    expect(fixture.componentInstance['loadState']()).toBe('loading');
    httpMock.expectOne('/api/applications').flush(APPS);
  });

  it('default state: renders the form once applications resolve, submit disabled until required fields are filled', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/applications').flush(APPS);
    await settle(fixture);

    expect(fixture.componentInstance['loadState']()).toBe('ready');
    expect(fixture.componentInstance['canSubmit']()).toBeFalse();

    fillRequiredFields(fixture);
    await settle(fixture);
    expect(fixture.componentInstance['canSubmit']()).toBeTrue();
  });

  it('empty state: no accessible applications explains the IQ entitlement requirement', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/applications').flush([]);
    await settle(fixture);

    expect(fixture.componentInstance['loadState']()).toBe('empty');
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text.toLowerCase()).toContain('nexus iq');
  });

  it('error state: an unreachable IQ shows the server message with a retry, not a fabricated one', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/applications').flush({ detail: 'Nexus IQ is unreachable: boom' }, { status: 503, statusText: 'Service Unavailable' });
    await settle(fixture);

    expect(fixture.componentInstance['loadState']()).toBe('error');
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Nexus IQ is unreachable: boom');
  });

  it(
    'each admission check reports independently: a report failure shows only the report check as failed, ' +
      'with an actionable message',
    async () => {
      const fixture = await create();
      httpMock.expectOne('/api/applications').flush(APPS);
      await settle(fixture);
      fillRequiredFields(fixture);

      const submitPromise = fixture.componentInstance['submit']();
      httpMock
        .expectOne('/api/assessments')
        .flush(
          { detail: { check: 'report', message: 'the report has been purged — re-scan and try again' } },
          { status: 422, statusText: 'Unprocessable Content' },
        );
      await submitPromise;
      await settle(fixture);

      const rows = fixture.componentInstance['checkRows']();
      expect(rows.find((r) => r.check === 'report')?.status).toBe('fail');
      expect(rows.find((r) => r.check === 'artifact')?.status).toBe('pending');
      const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
      expect(text).toContain('re-scan and try again');
    },
  );

  it('an artifact-check failure implies the report check already passed (checks are sequential and fail-fast)', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/applications').flush(APPS);
    await settle(fixture);
    fillRequiredFields(fixture);

    const submitPromise = fixture.componentInstance['submit']();
    httpMock
      .expectOne('/api/assessments')
      .flush({ detail: { check: 'artifact', message: 'artifact not found at that coordinate' } }, { status: 422, statusText: 'Unprocessable Content' });
    await submitPromise;
    await settle(fixture);

    const rows = fixture.componentInstance['checkRows']();
    expect(rows.find((r) => r.check === 'report')?.status).toBe('pass');
    expect(rows.find((r) => r.check === 'artifact')?.status).toBe('fail');
  });

  it(
    'a provenance mismatch is a HARD STOP: it renders a danger callout (never a dismissible warning) and blocks ' +
      'Submit until the artifact value actually changes',
    async () => {
      const fixture = await create();
      httpMock.expectOne('/api/applications').flush(APPS);
      await settle(fixture);
      fillRequiredFields(fixture);

      const submitPromise = fixture.componentInstance['submit']();
      httpMock.expectOne('/api/assessments').flush(
        { detail: { check: 'provenance', message: '71/96 report components found in the artifact (74%) — mismatch' } },
        { status: 422, statusText: 'Unprocessable Content' },
      );
      await submitPromise;
      await settle(fixture);

      const html = (fixture.nativeElement as HTMLElement).innerHTML;
      expect(html).toContain('callout--danger');
      expect(html).toContain('Use a different artifact');
      // Re-clicking Submit without changing anything must stay blocked.
      expect(fixture.componentInstance['canSubmit']()).toBeFalse();

      // Editing the artifact value is what lifts the block — not merely re-clicking submit.
      fixture.componentInstance['artifactCoordinates'].set('artifactory.example.com/payments-api:1.14.3');
      await settle(fixture);
      expect(fixture.componentInstance['canSubmit']()).toBeTrue();
    },
  );

  it('"Use a different artifact" clears the artifact field and the block, but does not itself re-enable Submit', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/applications').flush(APPS);
    await settle(fixture);
    fillRequiredFields(fixture);

    const submitPromise = fixture.componentInstance['submit']();
    httpMock.expectOne('/api/assessments').flush(
      { detail: { check: 'provenance', message: 'mismatch' } },
      { status: 422, statusText: 'Unprocessable Content' },
    );
    await submitPromise;
    await settle(fixture);

    fixture.componentInstance['useDifferentArtifact']();
    await settle(fixture);

    expect(fixture.componentInstance['artifactCoordinates']()).toBe('');
    expect(fixture.componentInstance['canSubmit']()).toBeFalse(); // artifact is now empty, still required
    expect((fixture.nativeElement as HTMLElement).innerHTML).not.toContain('callout--danger');
  });

  it('a successful submit navigates straight to the Assessment Result screen', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/applications').flush(APPS);
    await settle(fixture);
    fillRequiredFields(fixture);

    const submitPromise = fixture.componentInstance['submit']();
    const req = httpMock.expectOne('/api/assessments');
    expect(req.request.body.application_id).toBe('payments-api');
    expect(req.request.body.report_id).toBe('38ef4d1f');
    req.flush({ id: 'asm-9001', application_id: 'payments-api' });
    await submitPromise;

    expect(router.navigate).toHaveBeenCalledWith(['/assessments', 'asm-9001', 'result']);
  });

  it('extracts the report id from a pasted report URL', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/applications').flush(APPS);
    await settle(fixture);
    fillRequiredFields(fixture);
    fixture.componentInstance['reportRef'].set('https://iq.example.com/assets/index.html#/applicationReport/payments-api/38ef4d1f');

    const submitPromise = fixture.componentInstance['submit']();
    const req = httpMock.expectOne('/api/assessments');
    expect(req.request.body.report_id).toBe('38ef4d1f');
    req.flush({ id: 'asm-1' });
    await submitPromise;
  });

  it('distinguishes "Nexus IQ is unreachable" from a collection failure after admission succeeded', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/applications').flush(APPS);
    await settle(fixture);
    fillRequiredFields(fixture);

    const submitPromise = fixture.componentInstance['submit']();
    httpMock.expectOne('/api/assessments').flush({ detail: 'evidence collection failed after admission succeeded: boom' }, { status: 502, statusText: 'Bad Gateway' });
    await submitPromise;
    await settle(fixture);

    expect(fixture.componentInstance['submitError']()).toContain('Admission passed');
  });

  it('prefills from query params ("Fix and resubmit" from My Assessments)', async () => {
    const fixture = await create({ applicationId: 'ledger-svc', reportRef: 'abc123', note: 'previous note' });
    httpMock.expectOne('/api/applications').flush(APPS);
    await settle(fixture);

    expect(fixture.componentInstance['applicationId']()).toBe('ledger-svc');
    expect(fixture.componentInstance['reportRef']()).toBe('abc123');
    expect(fixture.componentInstance['requesterNote']()).toBe('previous note');
  });
});
