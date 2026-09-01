import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { AuthApiService } from './auth-api.service';
import type { IdentityResponse } from './models';

describe('AuthApiService', () => {
  let service: AuthApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(AuthApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('login() POSTs credentials to /api/auth/login and returns identity', () => {
    let result: IdentityResponse | undefined;
    service.login({ username: 'reviewer1', password: 'secret' }).subscribe((r) => (result = r));

    const req = httpMock.expectOne('/api/auth/login');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ username: 'reviewer1', password: 'secret' });
    req.flush({ username: 'reviewer1', roles: ['reviewer'] });

    expect(result).toEqual({ username: 'reviewer1', roles: ['reviewer'] });
  });

  it('me() GETs /api/auth/me', () => {
    service.me().subscribe();
    const req = httpMock.expectOne('/api/auth/me');
    expect(req.request.method).toBe('GET');
    req.flush({ username: 'reviewer1', roles: ['reviewer'] });
  });

  it('logout() POSTs to /api/auth/logout with an empty body', () => {
    service.logout().subscribe();
    const req = httpMock.expectOne('/api/auth/logout');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({});
    req.flush({ status: 'logged_out' });
  });
});
