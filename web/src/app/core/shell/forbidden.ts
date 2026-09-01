import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink } from '@angular/router';

/**
 * Where `capabilityGuard` sends a signed-in session that navigated (by
 * typed URL, a stale bookmark, or a nav item that used to apply) to a
 * screen its roles do not grant. A UX courtesy only — see
 * `capability.guard.ts`'s docstring: the server refuses the underlying
 * request either way.
 */
@Component({
  selector: 'app-forbidden',
  imports: [RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="page">
      <div class="page__head">
        <div>
          <p class="eyebrow">403</p>
          <h1>Not available for your role</h1>
          <p class="sub">
            None of your roles grant access to that screen. If you believe this is wrong, contact your AppSec
            administrator about your role assignment.
          </p>
        </div>
      </div>
      <a class="link-btn" routerLink="/">Back to your dashboard</a>
    </div>
  `,
})
export class Forbidden {}
