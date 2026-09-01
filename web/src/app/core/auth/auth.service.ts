import { Injectable, computed, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { AuthApiService, type IdentityResponse } from '../api';
import { type Capability, hasCapability } from './capabilities';

/**
 * The session's client-side state: a signal, not a service you poll.
 *
 * **Triple state, deliberately** — `identity()` is `undefined` until the
 * app's first `GET /api/auth/me` resolves, then either `null` (no valid
 * session) or an `IdentityResponse` (signed in). Collapsing this to
 * `IdentityResponse | null` would force `authGuard` to treat "haven't
 * checked yet" the same as "not signed in", which sends every user to
 * `/login` for an instant on every hard refresh before the check completes
 * — `auth.guard.ts`'s `filter(v => v !== undefined)` is the other half of
 * this design.
 *
 * **Roles come only from the server.** This service never decodes the
 * session cookie itself (it is `httpOnly` — it cannot) and never lets a
 * caller set `roles` directly; the only way `identity()` changes is a
 * successful `login()` response or a successful `bootstrap()`/`refresh()`
 * call to `GET /api/auth/me`. Every screen that renders based on
 * `roles()`/`hasCapability()` is rendering a courtesy, never an
 * enforcement — see `capabilities.ts`'s module docstring.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly api = inject(AuthApiService);

  private readonly _identity = signal<IdentityResponse | null | undefined>(undefined);

  /** `undefined` = not yet resolved; `null` = resolved, signed out; else signed in. */
  readonly identity = this._identity.asReadonly();

  readonly isBootstrapped = computed(() => this._identity() !== undefined);
  readonly isAuthenticated = computed(() => this._identity() != null);
  readonly username = computed(() => this._identity()?.username ?? null);
  readonly roles = computed<string[]>(() => this._identity()?.roles ?? []);

  /**
   * Resolves the initial session state from `GET /api/auth/me`. Called once
   * at app bootstrap (`app.config.ts`), before the router's first
   * navigation, so `authGuard`'s first evaluation already has a real
   * answer rather than racing it.
   *
   * A 401 here (no session) is expected, not an error — it means
   * `identity()` should settle to `null`, same as any other failure to
   * resolve a session (a network error reads the same way to this method:
   * "not currently signed in").
   */
  async bootstrap(): Promise<void> {
    try {
      const identity = await firstValueFrom(this.api.me());
      this._identity.set(identity);
    } catch {
      this._identity.set(null);
    }
  }

  /**
   * Re-resolves the session from the server. Unlike `bootstrap()`, this is
   * called mid-session (e.g. after the session-expired interceptor's
   * redirect, once the user is back on `/login`) and lets a genuine error
   * propagate to the caller rather than silently going to `null` — a
   * caller that explicitly asked to refresh wants to know if it failed.
   */
  async refresh(): Promise<IdentityResponse> {
    const identity = await firstValueFrom(this.api.me());
    this._identity.set(identity);
    return identity;
  }

  /**
   * Throws on any non-2xx — `LoginComponent` catches it and renders the
   * server's own message (never inventing one; see that component and
   * `docs/design/ui-spec.md` screen 1's error-state rule).
   */
  async login(username: string, password: string): Promise<IdentityResponse> {
    const identity = await firstValueFrom(this.api.login({ username, password }));
    this._identity.set(identity);
    return identity;
  }

  /**
   * Clears the session server-side, then locally regardless of whether the
   * POST succeeded — a stale cookie is still "signed out" from the user's
   * point of view.
   */
  async logout(): Promise<void> {
    try {
      await firstValueFrom(this.api.logout());
    } catch {
      // Session may already be invalid server-side; clear local state anyway.
    }
    this._identity.set(null);
  }

  /**
   * Called by `session-expired.interceptor.ts` when an authenticated
   * request comes back 401 mid-session. Synchronous and local only — the
   * interceptor is responsible for the navigation back to `/login`; this
   * method only makes `isAuthenticated()` immediately correct so nothing
   * else in the app keeps rendering as if the old session were still good.
   */
  clearSession(): void {
    this._identity.set(null);
  }

  hasCapability(capability: Capability): boolean {
    return hasCapability(this.roles(), capability);
  }
}
