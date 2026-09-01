import { inject } from '@angular/core';
import { HttpErrorResponse, type HttpInterceptorFn } from '@angular/common/http';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';

import { AuthService } from './auth.service';

/**
 * Catches a 401 arriving mid-session — the server no longer recognises a
 * session this app believed was good, whether because it expired
 * (`SESSION_TTL_HOURS`) or was revoked — and sends the user back to
 * `/login` with `returnUrl` set to wherever they were, so the current
 * screen is not simply lost.
 *
 * **Excludes `POST /api/auth/login` and `GET /api/auth/me`.** Both are
 * "identity resolution" calls `AuthService` already handles directly
 * (`login()`'s caller renders the 401 as "wrong credentials"; `bootstrap()`
 * and `refresh()` already catch their own 401 and settle `identity()` to
 * `null`), not a mid-session expiry:
 *   - `login`'s 401 means "this credential did not check out" — reacting to
 *     it here would also be wrong for the case where an already-authenticated
 *     user opens `/login` and mistypes a password: this interceptor would
 *     otherwise clear their still-good existing session over an unrelated
 *     failed attempt.
 *   - `me`'s 401 on the initial bootstrap call is the expected shape of "not
 *     signed in yet", not an expiry of anything.
 *
 * Every other endpoint's 401 is treated as "was authenticated, now is not"
 * — see `docs/design/ui-spec.md`'s Task 2 test: "a 401 mid-session returns
 * to login without losing the current URL."
 */
export const sessionExpiredInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  const router = inject(Router);

  const isIdentityCall = req.url.endsWith('/api/auth/login') || req.url.endsWith('/api/auth/me');

  return next(req).pipe(
    catchError((error: unknown) => {
      if (!isIdentityCall && error instanceof HttpErrorResponse && error.status === 401) {
        auth.clearSession();
        void router.navigate(['/login'], { queryParams: { returnUrl: router.url } });
      }
      return throwError(() => error);
    }),
  );
};
