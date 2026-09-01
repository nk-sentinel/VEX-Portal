import type { Routes } from '@angular/router';

import { authGuard } from './core/auth/auth.guard';
import { capabilityGuard } from './core/auth/capability.guard';
import { landingRedirectGuard } from './core/shell/landing-redirect.guard';

/**
 * `/login` and `/forbidden` are public/guard-target routes outside the
 * shell. Every other route is a child of the shell (`authGuard` on the
 * parent covers all of them at once) and, where it maps to a nav item
 * (`core/shell/nav.ts`), carries the matching `capabilityGuard` so typing
 * the URL directly is refused the same way the nav already hides it —
 * see that guard's docstring: a UX courtesy, the server enforces
 * regardless.
 *
 * Screens 2–9 (`docs/plans/2026-09-01-screens.md` Tasks 3–5) are not built
 * yet; every one of these `loadComponent`s resolves to
 * `RouteStub` today. Wiring the real paths now, rather than leaving this
 * task's shell pointed at nothing, is what makes the nav-visibility and
 * guard tests this task requires exercise the real route table.
 */
export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () => import('./features/auth/login/login').then((m) => m.Login),
  },
  {
    path: 'forbidden',
    loadComponent: () => import('./core/shell/forbidden').then((m) => m.Forbidden),
  },
  {
    path: '',
    loadComponent: () => import('./core/shell/shell').then((m) => m.Shell),
    canActivate: [authGuard],
    children: [
      {
        path: '',
        pathMatch: 'full',
        canActivate: [landingRedirectGuard],
        children: [],
      },
      {
        path: 'assessments/new',
        canActivate: [capabilityGuard('raise_assessment')],
        loadComponent: () => import('./core/shell/route-stub').then((m) => m.RouteStub),
        data: { title: 'New Assessment' },
      },
      {
        path: 'assessments',
        canActivate: [capabilityGuard('raise_assessment')],
        loadComponent: () => import('./core/shell/route-stub').then((m) => m.RouteStub),
        data: { title: 'My Assessments' },
      },
      {
        path: 'review',
        canActivate: [capabilityGuard('view_queue')],
        loadComponent: () => import('./core/shell/route-stub').then((m) => m.RouteStub),
        data: { title: 'Review Queue' },
      },
      {
        path: 'dashboard',
        canActivate: [capabilityGuard('view_dashboard')],
        loadComponent: () => import('./core/shell/route-stub').then((m) => m.RouteStub),
        data: { title: 'Dashboard' },
      },
      {
        path: 'risk-acceptance',
        canActivate: [capabilityGuard('view_risk_acceptance')],
        loadComponent: () => import('./core/shell/route-stub').then((m) => m.RouteStub),
        data: { title: 'Risk Acceptance Queue' },
      },
      {
        path: 'admin/rules',
        canActivate: [capabilityGuard('manage_rules')],
        loadComponent: () => import('./core/shell/route-stub').then((m) => m.RouteStub),
        data: { title: 'Rules & Thresholds' },
      },
      // Unknown path inside the shell -> back through the landing redirect,
      // never to /login — a signed-in user who mistyped a URL should not
      // see a screen that reads as "your session expired".
      { path: '**', redirectTo: '' },
    ],
  },
  { path: '**', redirectTo: '' },
];
