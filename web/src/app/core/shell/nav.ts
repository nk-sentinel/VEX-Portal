import type { Capability } from '../auth/capabilities';

/**
 * The rail's nav items, each gated by the capability that would let the
 * destination screen do anything useful — matching
 * `docs/design/ui-spec.md`'s navigation map (screen 1's role-based
 * landing) and `backend/app/services/authorization.py`'s
 * `CAPABILITY_ROLES`.
 *
 * `icon` is a plain character in `--font-mono`, matching the mockup's own
 * convention (`⌕`, `§`, the outcome glyphs `✓ ✗ ▲ ⚑`) — never a ligature
 * icon font, which VEX has no dependency on (see
 * `web/src/assets/fonts/fonts.scss`).
 *
 * Screens 2–9 do not exist yet (Tasks 3–5) — every route below currently
 * resolves to `RouteStubComponent`, a clearly-labelled placeholder. Wiring
 * the nav to real paths now, rather than leaving it to a later task, means
 * the rail's role-gating (this task's own test requirement) is exercised
 * against the real route table from the start.
 */
export interface NavItem {
  readonly label: string;
  readonly route: string;
  readonly icon: string;
  readonly capability: Capability;
}

export const NAV_ITEMS: readonly NavItem[] = [
  { label: 'New Assessment', route: '/assessments/new', icon: '+', capability: 'raise_assessment' },
  { label: 'My Assessments', route: '/assessments', icon: '≡', capability: 'raise_assessment' },
  { label: 'Review Queue', route: '/review', icon: '▤', capability: 'view_queue' },
  { label: 'Dashboard', route: '/dashboard', icon: '◔', capability: 'view_dashboard' },
  { label: 'Risk Acceptance', route: '/risk-acceptance', icon: '⚑', capability: 'view_risk_acceptance' },
  { label: 'Rules & Thresholds', route: '/admin/rules', icon: '⚙', capability: 'manage_rules' },
];
