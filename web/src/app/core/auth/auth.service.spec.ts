import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { AuthService } from './auth.service';

describe('AuthService', () => {
  let service: AuthService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(AuthService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('starts in the unresolved (undefined) state before bootstrap()', () => {
    expect(service.identity()).toBeUndefined();
    expect(service.isBootstrapped()).toBeFalse();
    expect(service.isAuthenticated()).toBeFalse();
  });

  it('bootstrap() settles to the identity on a successful /me', async () => {
    const promise = service.bootstrap();
    httpMock.expectOne('/api/auth/me').flush({ username: 'reviewer1', roles: ['reviewer'] });
    await promise;

    expect(service.isBootstrapped()).toBeTrue();
    expect(service.isAuthenticated()).toBeTrue();
    expect(service.username()).toBe('reviewer1');
    expect(service.roles()).toEqual(['reviewer']);
  });

  it('bootstrap() settles to null (signed out), not an error, on a 401', async () => {
    const promise = service.bootstrap();
    httpMock.expectOne('/api/auth/me').flush({ detail: 'not authenticated' }, { status: 401, statusText: 'Unauthorized' });
    await promise;

    expect(service.isBootstrapped()).toBeTrue();
    expect(service.isAuthenticated()).toBeFalse();
    expect(service.identity()).toBeNull();
  });

  it('login() sets the identity on success', async () => {
    const promise = service.login('reviewer1', 'correct-password');
    httpMock.expectOne('/api/auth/login').flush({ username: 'reviewer1', roles: ['reviewer'] });
    await promise;

    expect(service.isAuthenticated()).toBeTrue();
    expect(service.username()).toBe('reviewer1');
  });

  it('login() propagates a failure (never swallowed) so the caller can render the server message', async () => {
    const promise = service.login('reviewer1', 'wrong-password');
    const expectation = httpMock.expectOne('/api/auth/login');
    expectation.flush({ detail: 'invalid username or password' }, { status: 401, statusText: 'Unauthorized' });

    await expectAsync(promise).toBeRejected();
    // A failed login must not silently mark the caller as signed in.
    expect(service.isAuthenticated()).toBeFalse();
  });

  it('logout() clears the identity even if the server call fails', async () => {
    // Get into a signed-in state first.
    const loginPromise = service.login('reviewer1', 'correct-password');
    httpMock.expectOne('/api/auth/login').flush({ username: 'reviewer1', roles: ['reviewer'] });
    await loginPromise;
    expect(service.isAuthenticated()).toBeTrue();

    const logoutPromise = service.logout();
    httpMock.expectOne('/api/auth/logout').flush('server error', { status: 500, statusText: 'Server Error' });
    await logoutPromise;

    expect(service.isAuthenticated()).toBeFalse();
    expect(service.identity()).toBeNull();
  });

  it('clearSession() synchronously clears the identity (used by the session-expired interceptor)', async () => {
    const loginPromise = service.login('reviewer1', 'correct-password');
    httpMock.expectOne('/api/auth/login').flush({ username: 'reviewer1', roles: ['reviewer'] });
    await loginPromise;

    service.clearSession();

    expect(service.isAuthenticated()).toBeFalse();
    expect(service.identity()).toBeNull();
  });

  it('hasCapability() reflects the current roles', async () => {
    const promise = service.login('reviewer1', 'correct-password');
    httpMock.expectOne('/api/auth/login').flush({ username: 'reviewer1', roles: ['reviewer'] });
    await promise;

    expect(service.hasCapability('view_queue')).toBeTrue();
    expect(service.hasCapability('manage_rules')).toBeFalse();
  });
});
