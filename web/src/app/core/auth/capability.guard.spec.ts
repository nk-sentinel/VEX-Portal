import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import type { ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { UrlTree, provideRouter } from '@angular/router';
import { type Observable, firstValueFrom } from 'rxjs';

import { capabilityGuard } from './capability.guard';
import { AuthService } from './auth.service';

describe('capabilityGuard', () => {
  let auth: AuthService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    auth = TestBed.inject(AuthService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  function run(url: string, ...capabilities: Parameters<typeof capabilityGuard>): Promise<boolean | UrlTree> {
    return TestBed.runInInjectionContext(() => {
      const guard = capabilityGuard(...capabilities);
      const result = guard({} as ActivatedRouteSnapshot, { url } as RouterStateSnapshot) as Observable<
        boolean | UrlTree
      >;
      return firstValueFrom(result);
    });
  }

  it('allows a session holding one of the required capabilities', async () => {
    const p = auth.bootstrap();
    httpMock.expectOne('/api/auth/me').flush({ username: 'reviewer1', roles: ['reviewer'] });
    await p;

    expect(await run('/review', 'view_queue')).toBeTrue();
  });

  it('sends a session lacking every required capability to /forbidden — never lets the route mount', async () => {
    const p = auth.bootstrap();
    httpMock.expectOne('/api/auth/me').flush({ username: 'requester1', roles: ['requester'] });
    await p;

    const result = await run('/admin/rules', 'manage_rules');
    expect(result).toBeInstanceOf(UrlTree);
    expect((result as UrlTree).toString()).toContain('/forbidden');
  });

  it('sends a signed-out session to /login with returnUrl, same as authGuard', async () => {
    const p = auth.bootstrap();
    httpMock.expectOne('/api/auth/me').flush({ detail: 'nope' }, { status: 401, statusText: 'Unauthorized' });
    await p;

    const result = await run('/review', 'view_queue');
    expect(result).toBeInstanceOf(UrlTree);
    const tree = result as UrlTree;
    expect(tree.toString()).toContain('/login');
    expect(tree.queryParams['returnUrl']).toBe('/review');
  });

  it('allows a session holding ANY of several listed capabilities', async () => {
    const p = auth.bootstrap();
    httpMock.expectOne('/api/auth/me').flush({ username: 'auditor1', roles: ['auditor'] });
    await p;

    // auditor holds view_queue but not commit_determination — either is enough.
    expect(await run('/review', 'view_queue', 'commit_determination')).toBeTrue();
  });
});
