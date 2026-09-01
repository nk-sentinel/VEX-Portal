import { inject } from '@angular/core';
import { toObservable } from '@angular/core/rxjs-interop';
import { type CanActivateFn, Router, type UrlTree } from '@angular/router';
import { type Observable, filter, first, map } from 'rxjs';

import type { Capability } from './capabilities';
import { hasCapability } from './capabilities';
import { AuthService } from './auth.service';

/**
 * Blocks a route the signed-in session holds none of the given
 * capabilities for, sending it to `/forbidden` instead of letting the
 * screen mount, fire a request that was always going to be refused, and
 * render whatever error state that screen has for "the server said no".
 *
 * **This is a UX gate, never the enforcement point.** Every action route
 * on the server depends on its own `requires(Capability)`
 * (`backend/app/api/deps.py`) regardless of what this guard decided; a
 * response that reaches this guard's "allow" branch can still be refused
 * server-side (rule 3). The one thing this guard actually buys the user is
 * not being sent to a screen whose every request 403s.
 *
 * Mirrors `authGuard`'s `filter(v => v !== undefined)` — see that guard's
 * docstring.
 */
export function capabilityGuard(...capabilities: Capability[]): CanActivateFn {
  return (_route, state): Observable<boolean | UrlTree> => {
    const auth = inject(AuthService);
    const router = inject(Router);

    return toObservable(auth.identity).pipe(
      filter((identity) => identity !== undefined),
      first(),
      map((identity) => {
        if (identity === null) {
          return router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });
        }
        return capabilities.some((capability) => hasCapability(identity.roles, capability))
          ? true
          : router.createUrlTree(['/forbidden']);
      }),
    );
  };
}
