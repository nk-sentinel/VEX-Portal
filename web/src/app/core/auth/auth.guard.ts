import { inject } from '@angular/core';
import { toObservable } from '@angular/core/rxjs-interop';
import { type CanActivateFn, Router, type UrlTree } from '@angular/router';
import { type Observable, filter, first, map } from 'rxjs';

import { AuthService } from './auth.service';

/**
 * Blocks every route under the shell for a signed-out visitor, sending them
 * to `/login` with `returnUrl` set to the URL they asked for — so a
 * bookmark, a shared link, or a session that expired mid-navigation lands
 * back where the user meant to be after they sign back in, rather than on
 * whatever the default landing page is.
 *
 * `toObservable(auth.identity).pipe(filter(v => v !== undefined), first())`
 * is the guard-side half of `AuthService`'s triple-state design: without
 * the `filter`, this would fire on the signal's initial `undefined` value
 * and redirect every user to `/login` on every hard refresh, before
 * `bootstrap()` (`app.config.ts`) has had a chance to resolve the real
 * session state.
 */
export const authGuard: CanActivateFn = (_route, state): Observable<boolean | UrlTree> => {
  const auth = inject(AuthService);
  const router = inject(Router);

  return toObservable(auth.identity).pipe(
    filter((identity) => identity !== undefined),
    first(),
    map((identity) =>
      identity !== null ? true : router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } }),
    ),
  );
};
