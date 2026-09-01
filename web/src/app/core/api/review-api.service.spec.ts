import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { ReviewApiService } from './review-api.service';

describe('ReviewApiService', () => {
  let service: ReviewApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ReviewApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('listFindings() sends no query params when called with none', () => {
    service.listFindings().subscribe();
    const req = httpMock.expectOne((r) => r.url === '/api/review/findings');
    expect(req.request.params.keys().length).toBe(0);
    req.flush([]);
  });

  it('listFindings() repeats the "state" key for an array value (FastAPI list[str] convention)', () => {
    service.listFindings({ state: ['needs_review', 'affected'], sla: 'breaching' }).subscribe();
    const req = httpMock.expectOne(
      (r) => r.url === '/api/review/findings' && r.params.getAll('state')?.join(',') === 'needs_review,affected',
    );
    expect(req.request.params.get('sla')).toBe('breaching');
    req.flush([]);
  });

  it('getFinding() GETs the drawer payload by id', () => {
    service.getFinding('finding-1').subscribe();
    httpMock.expectOne('/api/review/findings/finding-1').flush({});
  });

  it('decide() POSTs the commit body to .../decide', () => {
    service.decide('finding-1', { outcome: 'not_affected', justification: 'code_not_present' }).subscribe();
    const req = httpMock.expectOne('/api/review/findings/finding-1/decide');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ outcome: 'not_affected', justification: 'code_not_present' });
    req.flush({});
  });

  it('recommend() POSTs to .../recommend, never .../decide', () => {
    service.recommend('finding-1', { outcome: 'not_affected' }).subscribe();
    const req = httpMock.expectOne('/api/review/findings/finding-1/recommend');
    expect(req.request.method).toBe('POST');
    req.flush({ finding_id: 'finding-1', outcome: 'not_affected', recorded_by: 'r', recorded_at: 'now' });
  });
});
