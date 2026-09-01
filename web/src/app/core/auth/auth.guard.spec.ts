import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import type { ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { Router, UrlTree, provideRouter } from '@angular/router';
import { type Observable, firstValueFrom } from 'rxjs';

import { authGuard } from './auth.guard';
import { AuthService } from './auth.service';

describe('authGuard', () => {
  let auth: AuthService;
  let router: Router;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    auth = TestBed.inject(AuthService);
    router = TestBed.inject(Router);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  function runGuard(url: string): Promise<boolean | UrlTree> {
    return TestBed.runInInjectionContext(() => {
      const result = authGuard(
        {} as ActivatedRouteSnapshot,
        { url } as RouterStateSnapshot,
      ) as Observable<boolean | UrlTree>;
      return firstValueFrom(result);
    });
  }

  it('allows navigation once the session resolves to signed-in', async () => {
    const bootstrapPromise = auth.bootstrap();
    httpMock.expectOne('/api/auth/me').flush({ username: 'reviewer1', roles: ['reviewer'] });
    await bootstrapPromise;

    const result = await runGuard('/review');
    expect(result).toBeTrue();
  });

  it('redirects to /login with returnUrl once the session resolves to signed-out', async () => {
    const bootstrapPromise = auth.bootstrap();
    httpMock.expectOne('/api/auth/me').flush({ detail: 'nope' }, { status: 401, statusText: 'Unauthorized' });
    await bootstrapPromise;

    const result = await runGuard('/review');
    expect(result).toBeInstanceOf(UrlTree);
    const tree = result as UrlTree;
    expect(tree.toString()).toContain('/login');
    expect(tree.queryParams['returnUrl']).toBe('/review');
  });

  it('waits for the unresolved (undefined) state to settle before deciding — never redirects on a hard refresh before bootstrap completes', async () => {
    // identity() is still undefined here — bootstrap() has not been called.
    const resultPromise = runGuard('/review');

    // The guard must not have resolved yet (it needs a resolved identity()).
    let settled = false;
    void resultPromise.then(() => (settled = true));
    await Promise.resolve();
    expect(settled).toBeFalse();

    // Now resolve it — the guard should then complete.
    const bootstrapPromise = auth.bootstrap();
    httpMock.expectOne('/api/auth/me').flush({ username: 'reviewer1', roles: ['reviewer'] });
    await bootstrapPromise;

    expect(await resultPromise).toBeTrue();
  });
});
