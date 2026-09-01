import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { ReactiveFormsModule, Validators, FormControl, FormGroup } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';

import { AuthService } from '../../../core/auth/auth.service';
import { ALL_ROLES, humanizeRole, landingRouteFor } from '../../../core/auth/capabilities';

/**
 * [1] Login / SSO landing.
 *
 * **Deviation from `docs/design/ui-mockups.html` and the "AD-backed SSO
 * redirect" framing in `docs/design/ui-spec.md` screen 1 — flagged per this
 * phase's process rule, not silently reconciled.** The live backend
 * (`POST /api/auth/login`, `app/api/auth.py`) has no SSO/OIDC/SAML redirect
 * endpoint at all — `AUTH_PROVIDER=local` checks a username/password pair
 * against the local `user` table (`app/auth/local.py`), and
 * `AUTH_PROVIDER=ldap` checks the same pair via an LDAP bind
 * (`app/auth/ldap.py`) — both a conventional credential POST, never a
 * redirect flow. There is no data source for an SSO button to hit. Task
 * 2's own brief already calls this a "Login form", which is what this
 * component is: a username/password form against `AuthService.login()`.
 * The mockup's "Sign in with corporate SSO" button is a Claude Design
 * placeholder interaction, not a real affordance this backend supports.
 *
 * **States** (ui-spec screen 1 names three — default, loading, error; no
 * "empty" state is defined for this screen, and none makes sense for a
 * credential form, so this component implements exactly those three):
 *   - *default* — the form, empty or mid-edit.
 *   - *loading* — a submission in flight; inputs and the button disable,
 *     the button reads "Signing in…" (the closest equivalent this backend
 *     has to "redirect in progress").
 *   - *error* — three distinguishable cases, echoing this phase's rule that
 *     "IQ is unreachable" and "artifact not found" must never share a
 *     message (screen 2's admission-checks table) applied here: a rejected
 *     credential (401, the server's own message, unmodified — provably not
 *     username-oracle-shaped); an unreachable directory (503, distinct
 *     wording); and a successful login carrying no recognised role, which
 *     names every role that grants access rather than saying
 *     "access denied" (ui-spec's own wording for this case).
 */
@Component({
  selector: 'app-login',
  imports: [ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './login.html',
})
export class Login {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  private redirected = false;

  protected readonly form = new FormGroup({
    username: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    password: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  });

  protected readonly submitting = signal(false);

  /** Set on a rejected credential or an unreachable auth service — cleared on the next submit. */
  protected readonly credentialError = signal<string | null>(null);

  /** Set when a login SUCCEEDS but the session carries no recognised role — see this class's docstring. */
  protected readonly noRoleSession = signal<{ username: string } | null>(null);

  protected readonly allRoleLabels = ALL_ROLES.map(humanizeRole);

  constructor() {
    // `provideAppInitializer` (app.config.ts) runs `AuthService.bootstrap()`
    // to completion before the router's first navigation, so `identity()`
    // is already resolved (never `undefined`) by the time this component
    // constructs — a signed-in visitor who lands on `/login` (a surviving
    // cookie, or `landing-redirect.guard.ts` sending a zero-role session
    // back here) is handled on construction; a fresh sign-in is handled
    // again by `submit()` calling the same method after `login()` resolves.
    this.checkIdentity();
  }

  /** Only ever navigates to a same-app relative path — never an open redirect via an absolute/`//` URL. */
  private safeReturnUrl(): string | null {
    const raw = this.route.snapshot.queryParamMap.get('returnUrl');
    if (!raw) return null;
    if (!raw.startsWith('/') || raw.startsWith('//')) return null;
    return raw;
  }

  /**
   * If the session is signed in with at least one recognised role, leaves
   * `/login` for `returnUrl` (if present and safe) or the role's landing
   * screen. A signed-in session with NO roles never navigates away from
   * here — `landingRouteFor([])` resolves back to `/login` itself, and
   * looping through this method again would either infinite-redirect or
   * just re-render the same thing, so it renders the explanatory error in
   * place instead.
   */
  private checkIdentity(): void {
    if (this.redirected) return;
    const identity = this.auth.identity();
    if (identity == null) return;
    if (identity.roles.length === 0) {
      this.noRoleSession.set({ username: identity.username });
      return;
    }
    this.redirected = true;
    const target = this.safeReturnUrl() ?? landingRouteFor(identity.roles);
    void this.router.navigateByUrl(target);
  }

  protected async submit(): Promise<void> {
    if (this.form.invalid || this.submitting()) {
      this.form.markAllAsTouched();
      return;
    }
    this.credentialError.set(null);
    this.noRoleSession.set(null);
    this.submitting.set(true);
    // `form.disable()`, not a `[disabled]` binding on each input — Angular
    // warns (and the binding loses) when a `[disabled]` attribute binding
    // and the `formControlName` directive both try to own the same
    // element's disabled state; the control's own `disabled` is the
    // supported way to disable a reactive-forms input.
    this.form.disable();
    const { username, password } = this.form.getRawValue();
    try {
      await this.auth.login(username, password);
      this.checkIdentity();
    } catch (error) {
      this.credentialError.set(Login.messageFor(error));
    } finally {
      this.submitting.set(false);
      this.form.enable();
    }
  }

  /**
   * Renders the server's own message verbatim wherever it sent one — never
   * a client-invented substitute — so a failed login is provably not a
   * username oracle (`app/api/auth.py`'s docstring: "same 401, same
   * message... whether the username exists or not").
   */
  private static messageFor(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (typeof error.error?.detail === 'string') {
        return error.error.detail;
      }
      if (error.status === 503) {
        return 'Authentication service unavailable. Try again shortly.';
      }
    }
    return 'Sign-in failed. Try again.';
  }
}
