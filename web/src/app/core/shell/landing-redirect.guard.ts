import { inject } from '@angular/core';
import type { CanActivateFn } from '@angular/router';
import { Router } from '@angular/router';

import { AuthService } from '../auth/auth.service';
import { landingRouteFor } from '../auth/capabilities';

/**
 * The shell's empty child route (`''`, i.e. visiting `/`) always redirects
 * — to whichever screen `landingRouteFor` picks for this session's roles.
 * A guard rather than a static `redirectTo` because the destination
 * depends on who is signed in; sits behind `authGuard` on the parent
 * route, so by the time this runs `identity()` is already resolved and
 * signed in.
 */
export const landingRedirectGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);
  return router.createUrlTree([landingRouteFor(auth.roles())]);
};
