import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Router, provideRouter } from '@angular/router';

import { AuthService } from './auth.service';
import { sessionExpiredInterceptor } from './session-expired.interceptor';

describe('sessionExpiredInterceptor', () => {
  let http: HttpClient;
  let httpMock: HttpTestingController;
  let router: Router;
  let auth: AuthService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([sessionExpiredInterceptor])),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    });
    http = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
    router = TestBed.inject(Router);
    auth = TestBed.inject(AuthService);
  });

  afterEach(() => httpMock.verify());

  async function signIn(): Promise<void> {
    const p = auth.bootstrap();
    httpMock.expectOne('/api/auth/me').flush({ username: 'reviewer1', roles: ['reviewer'] });
    await p;
  }

  it('a 401 from a protected endpoint redirects to /login preserving the current URL as returnUrl, and clears the session', async () => {
    await signIn();
    spyOn(router, 'navigate').and.resolveTo(true);
    spyOnProperty(router, 'url', 'get').and.returnValue('/review');

    http.get('/api/review/findings').subscribe({ error: () => undefined });
    httpMock.expectOne('/api/review/findings').flush({ detail: 'not authenticated' }, { status: 401, statusText: 'Unauthorized' });

    expect(auth.isAuthenticated()).toBeFalse();
    expect(router.navigate).toHaveBeenCalledWith(['/login'], { queryParams: { returnUrl: '/review' } });
  });

  it('still propagates the error to the caller after redirecting (does not swallow it)', async () => {
    await signIn();
    spyOn(router, 'navigate').and.resolveTo(true);

    let caughtStatus: number | undefined;
    http.get('/api/review/findings').subscribe({ error: (e) => (caughtStatus = e.status) });
    httpMock.expectOne('/api/review/findings').flush({}, { status: 401, statusText: 'Unauthorized' });

    expect(caughtStatus).toBe(401);
  });

  it('does NOT redirect or clear session on a 401 from POST /api/auth/login (a wrong-password attempt, not an expiry)', async () => {
    await signIn(); // an already-authenticated user who then mistypes a password elsewhere
    spyOn(router, 'navigate');

    http.post('/api/auth/login', { username: 'reviewer1', password: 'oops' }).subscribe({ error: () => undefined });
    httpMock.expectOne('/api/auth/login').flush({ detail: 'invalid username or password' }, { status: 401, statusText: 'Unauthorized' });

    expect(router.navigate).not.toHaveBeenCalled();
    // The existing, unrelated valid session must not have been torn down.
    expect(auth.isAuthenticated()).toBeTrue();
  });

  it('does NOT redirect on a 401 from GET /api/auth/me (the initial bootstrap check, not an expiry)', () => {
    spyOn(router, 'navigate');

    http.get('/api/auth/me').subscribe({ error: () => undefined });
    httpMock.expectOne('/api/auth/me').flush({ detail: 'not authenticated' }, { status: 401, statusText: 'Unauthorized' });

    expect(router.navigate).not.toHaveBeenCalled();
  });

  it('does not react to a non-401 error', async () => {
    await signIn();
    spyOn(router, 'navigate');

    http.get('/api/review/findings').subscribe({ error: () => undefined });
    httpMock.expectOne('/api/review/findings').flush({ detail: 'nope' }, { status: 403, statusText: 'Forbidden' });

    expect(router.navigate).not.toHaveBeenCalled();
    expect(auth.isAuthenticated()).toBeTrue();
  });
});
