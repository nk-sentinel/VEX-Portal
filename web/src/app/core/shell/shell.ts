import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { AuthService } from '../auth/auth.service';
import { humanizeRole } from '../auth/capabilities';
import { NAV_ITEMS, type NavItem } from './nav';

/**
 * The dark rail plus the routed content area — `docs/design/ui-spec.md`'s
 * shell, wrapping every screen behind `authGuard` (see `app.routes.ts`).
 *
 * **Nav visibility is a courtesy, not access control.** `visibleNavItems`
 * filters `NAV_ITEMS` by capability so the rail only ever shows what this
 * session can use — this task's own test requirement — but every one of
 * those routes is independently guarded by `capabilityGuard` (so typing a
 * hidden URL does not load the screen) and every action within a screen is
 * independently enforced by the server regardless of either (rule 3).
 *
 * **The persona indicator shows every role this session holds** (not just
 * the one driving the landing redirect) — `docs/design/ui-spec.md` screen
 * 1 calls for "a persona indicator showing who you are and what roles you
 * hold", plural. A session with more than one role is real (see
 * `capabilities.ts`'s `landingRouteFor` docstring on the priority-order
 * judgement call that situation forces elsewhere) and should read as
 * holding all of them, not just the one that happened to pick a landing
 * page.
 */
@Component({
  selector: 'app-shell',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './shell.html',
})
export class Shell {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected readonly username = this.auth.username;
  protected readonly roleLabels = computed(() => this.auth.roles().map(humanizeRole));

  protected readonly visibleNavItems = computed<NavItem[]>(() =>
    NAV_ITEMS.filter((item) => this.auth.hasCapability(item.capability)),
  );

  protected async signOut(): Promise<void> {
    await this.auth.logout();
    await this.router.navigate(['/login']);
  }
}
