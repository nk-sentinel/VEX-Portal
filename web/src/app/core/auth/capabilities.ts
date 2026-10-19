/**
 * Client-side mirror of `backend/app/services/authorization.py`'s
 * `Capability` enum and `CAPABILITY_ROLES` map.
 *
 * **This mirror is a rendering convenience only — never the enforcement
 * point.** Every route on the server independently depends on
 * `requires(Capability.X)` (`backend/app/api/deps.py`) and, where
 * separation of duties applies, a second service-layer check
 * (`assert_may_commit_own_determination`). Hiding a nav item or disabling a
 * button here is a courtesy to a user who cannot use it anyway; it is never
 * what stops them. If this map drifts from the server's, the worst case is
 * a control that renders when the server will still refuse it (caught
 * immediately by the resulting 403) or one that stays hidden when the
 * server would allow it (a usability bug, not a security one) — neither
 * case is a hole, because the server decides both times.
 *
 * Keep in sync BY HAND with `CAPABILITY_ROLES` in that file; there is no
 * shared source of truth across the Python/TypeScript boundary for this
 * phase (Task 1's hand-written API client has no schema for authorization
 * mappings — `Capability` and role names are strings, not part of the
 * OpenAPI document).
 */

/**
 * Mirrors `backend/app/repos/models.py`'s `Role` enum, five values.
 *
 * `'approver'` was merged into `'reviewer'` — one AppSec seat now reviews a
 * finding and commits the determination. The server still accepts the
 * retired value (`Role._missing_` maps it to `reviewer`, because stored
 * rows and signed session cookies outlive the code change), so a session
 * minted before the merge keeps working; this mirror deliberately does not
 * list it, since `hasCapability` already treats an unknown role as granting
 * nothing and the server is what decides.
 */
export type Role = 'requester' | 'reviewer' | 'auditor' | 'risk_manager' | 'admin';

export const ALL_ROLES: readonly Role[] = ['requester', 'reviewer', 'auditor', 'risk_manager', 'admin'];

/** Mirrors `backend/app/services/authorization.py`'s `Capability` enum. */
export type Capability =
  | 'raise_assessment'
  | 'view_queue'
  | 'recommend_determination'
  | 'commit_determination'
  | 'view_dashboard'
  | 'view_risk_acceptance'
  | 'manage_risk_acceptance'
  | 'manage_rules';

/**
 * Mirrors `backend/app/services/authorization.py`'s `CAPABILITY_ROLES`.
 *
 * `'admin'` appears in every row: the server grants it every capability
 * through `FULL_ACCESS_ROLES`, folded into each entry there rather than
 * listed per capability. It is written out longhand here so this stays a
 * flat mirror of the resolved table.
 */
export const CAPABILITY_ROLES: Readonly<Record<Capability, readonly Role[]>> = {
  raise_assessment: ['requester', 'admin'],
  view_queue: ['reviewer', 'auditor', 'admin'],
  recommend_determination: ['reviewer', 'admin'],
  commit_determination: ['reviewer', 'admin'],
  view_dashboard: ['auditor', 'admin'],
  view_risk_acceptance: ['risk_manager', 'auditor', 'admin'],
  manage_risk_acceptance: ['risk_manager', 'admin'],
  manage_rules: ['admin'],
};

/**
 * Whether holding any of `roles` (the server's own string list from
 * `IdentityResponse.roles` — not necessarily validated `Role` values, see
 * below) grants `capability`.
 *
 * `roles` is typed `readonly string[]`, not `readonly Role[]`: it comes
 * straight off the wire (`IdentityResponse.roles: string[]`), and treating
 * an unrecognised string as "grants nothing" (rather than throwing) is the
 * correct fail-closed behaviour if the server ever introduces a role this
 * mirror does not know about yet.
 */
export function hasCapability(roles: readonly string[], capability: Capability): boolean {
  return CAPABILITY_ROLES[capability].some((role) => roles.includes(role));
}

/**
 * [Screen] each role lands on after login, per `docs/design/ui-spec.md`'s
 * navigation map. Where a session holds more than one role, the first
 * match in this fixed priority order wins — the spec does not say what
 * should happen for a multi-role session, so this is a judgement call
 * flagged in the Task 1/2 report, not a documented requirement.
 */
const LANDING_ROUTE_BY_ROLE: Readonly<Record<Role, string>> = {
  requester: '/assessments',
  reviewer: '/review',
  auditor: '/dashboard',
  risk_manager: '/risk-acceptance',
  admin: '/admin/rules',
};

const LANDING_PRIORITY: readonly Role[] = ['requester', 'reviewer', 'auditor', 'risk_manager', 'admin'];

/** The route a signed-in session should land on, given its roles. */
export function landingRouteFor(roles: readonly string[]): string {
  const match = LANDING_PRIORITY.find((role) => roles.includes(role));
  return match ? LANDING_ROUTE_BY_ROLE[match] : '/login';
}

/** "risk_manager" -> "Risk Manager", for the persona indicator. */
export function humanizeRole(role: string): string {
  return role
    .split('_')
    .map((word) => (word.length > 0 ? word[0].toUpperCase() + word.slice(1) : word))
    .join(' ');
}
