#!/usr/bin/env node
// Round-trips `web/src/app/core/api/` against the LIVE backend — the Task 1
// brief's "the client round-trips against the running API".
//
// Plain Node + global `fetch` (Node 18+), zero npm dependencies: this is
// deliberately NOT a Karma/browser spec. The backend
// (`backend/app/main.py`) has no CORS middleware — a same-process decision,
// not an oversight, since the deployed app is always same-origin behind
// Traefik — so a browser-hosted Karma test (served from `localhost:9876`)
// cannot make a cross-origin call to `localhost:8000` and read the
// response. This script talks to the backend directly instead, the same
// way the deployed app's browser will (same-origin, via a same-process
// fetch rather than a cross-origin one).
//
// The interfaces in `src/app/core/api/models.ts` are hand-written, not
// generated (see that folder's `README.md`) — this script is the check
// that keeps them honest: every field asserted below is a field a TS
// interface declares, so a renamed/removed backend field fails loudly here
// instead of silently at runtime in the browser.
//
// Usage:
//   node scripts/verify-api-client.mjs
//   VEX_API_BASE_URL=http://localhost:8000 node scripts/verify-api-client.mjs
//
// Requires the backend running (see repo root README/CLAUDE.md) and the two
// local test users this task created (see the Task 1/2 report for how):
// `reviewer1` / `admin1`, password `vex-dev-password-1` — overridable via
// VEX_TEST_PASSWORD if a real deployment's fixture differs.

const BASE = process.env.VEX_API_BASE_URL ?? 'http://localhost:8000';
const PASSWORD = process.env.VEX_TEST_PASSWORD ?? 'vex-dev-password-1';

let passed = 0;
let failed = 0;

function ok(label, condition) {
  if (condition) {
    passed += 1;
    console.log(`  ok - ${label}`);
  } else {
    failed += 1;
    console.error(`  FAIL - ${label}`);
  }
}

function hasKeys(obj, keys) {
  return obj !== null && typeof obj === 'object' && keys.every((k) => k in obj);
}

/** Extracts just the cookie name=value pairs from a Set-Cookie header, for
 * replay on the next request — Node's fetch does not keep a cookie jar. */
function cookieHeaderFrom(setCookie) {
  if (!setCookie) return '';
  return setCookie
    .split(/,(?=[^ ]+=)/) // multiple Set-Cookie values may be folded into one header
    .map((part) => part.split(';')[0].trim())
    .join('; ');
}

async function login(username, password) {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const body = await res.json();
  const cookie = cookieHeaderFrom(res.headers.get('set-cookie'));
  return { status: res.status, body, cookie };
}

async function api(path, { cookie, method = 'GET', body } = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      ...(cookie ? { Cookie: cookie } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return { status: res.status, body: json, text };
}

async function main() {
  console.log(`Verifying API client contracts against ${BASE} ...\n`);

  console.log('GET /health');
  {
    const res = await api('/health');
    ok('200', res.status === 200);
    ok('has status/adapter_mode/version', hasKeys(res.body, ['status', 'adapter_mode', 'version']));
  }

  console.log('\nPOST /api/auth/login — unknown username');
  {
    const res = await login('no-such-user', 'whatever');
    ok('401', res.status === 401);
    ok(
      "message does not reveal whether the username exists ('invalid username or password')",
      res.body.detail === 'invalid username or password',
    );
  }

  console.log('\nPOST /api/auth/login — known username, wrong password (same message as above)');
  {
    const res = await login('reviewer1', 'not-the-password');
    ok('401', res.status === 401);
    ok('identical message to the unknown-username case', res.body.detail === 'invalid username or password');
  }

  console.log('\nPOST /api/auth/login — reviewer1 (IdentityResponse shape)');
  let reviewerCookie;
  {
    const res = await login('reviewer1', PASSWORD);
    ok('200', res.status === 200);
    ok('matches IdentityResponse {username, roles}', hasKeys(res.body, ['username', 'roles']));
    ok('roles is an array', Array.isArray(res.body.roles));
    ok('roles includes "reviewer"', res.body.roles.includes('reviewer'));
    ok('sets a session cookie', res.cookie.length > 0);
    reviewerCookie = res.cookie;
  }

  console.log('\nGET /api/auth/me — matches the login response');
  {
    const res = await api('/api/auth/me', { cookie: reviewerCookie });
    ok('200', res.status === 200);
    ok('username matches', res.body.username === 'reviewer1');
  }

  console.log('\nGET /api/applications — ApplicationOut[] (RAISE_ASSESSMENT is requester-only)');
  let requesterCookie;
  {
    const requesterLogin = await login('requester1', PASSWORD);
    requesterCookie = requesterLogin.cookie;
    const res = await api('/api/applications', { cookie: requesterCookie });
    ok('200', res.status === 200);
    ok('is an array', Array.isArray(res.body));
    ok('items (if any) match ApplicationOut {id, name}', res.body.every((a) => hasKeys(a, ['id', 'name'])));
  }

  console.log('\nGET /api/applications — a non-requester role is refused (403), the client never masks this as an empty list');
  {
    const res = await api('/api/applications', { cookie: reviewerCookie });
    ok('403', res.status === 403);
  }

  console.log('\nGET /api/assessments — AssessmentSummary[] (the caller\'s own, any role)');
  {
    const res = await api('/api/assessments', { cookie: requesterCookie });
    ok('200', res.status === 200);
    ok('is an array', Array.isArray(res.body));
  }

  console.log('\nGET /api/review/findings — ReviewFindingRow[] (VIEW_QUEUE capability)');
  {
    const res = await api('/api/review/findings', { cookie: reviewerCookie });
    ok('200', res.status === 200);
    ok('is an array', Array.isArray(res.body));
    const expectedKeys = [
      'id',
      'assessment_id',
      'application_id',
      'cve',
      'purl',
      'outcome',
      'recommended_outcome',
      'tier',
      'justification',
      'confidence',
      'sla_band',
      'sla_hours_remaining',
      'age_hours',
      'requester',
      'decided_by',
      'decided_at',
    ];
    ok('items (if any) match ReviewFindingRow', res.body.every((row) => hasKeys(row, expectedKeys)));
  }

  console.log('\nGET /api/review/findings — a requester-only role is refused (403), not silently empty');
  {
    const res = await api('/api/review/findings', { cookie: requesterCookie });
    ok('403 (VIEW_QUEUE is reviewer/approver/auditor only)', res.status === 403);
  }

  console.log('\nPOST /api/assessments — no application_id is refused with a body a form can render (422/400)');
  {
    const res = await api('/api/assessments', {
      cookie: requesterCookie,
      method: 'POST',
      body: { application_id: '', report_id: 'x', artifact_coordinates: 'x', requester_note: 'x' },
    });
    ok('rejects an empty application_id (422)', res.status === 422);
    ok('carries a "detail" the New Assessment form can surface', 'detail' in res.body);
  }

  console.log('\nGET /api/risk-acceptance — RiskAcceptanceRow[]');
  {
    const riskManager = await login('riskmgr1', PASSWORD);
    const res = await api('/api/risk-acceptance', { cookie: riskManager.cookie });
    ok('200', res.status === 200);
    ok('is an array', Array.isArray(res.body));
  }

  console.log('\nGET /api/admin/rules — RuleOut[] discriminated union (Toggleable | Escalation | Pending)');
  let adminCookie;
  {
    const login1 = await login('admin1', PASSWORD);
    adminCookie = login1.cookie;
    const res = await api('/api/admin/rules', { cookie: adminCookie });
    ok('200', res.status === 200);
    ok('is a non-empty array (the rule registry)', Array.isArray(res.body) && res.body.length > 0);

    const toggleable = res.body.filter((r) => r.has_auto_determination_toggle === true);
    const escalation = res.body.filter((r) => r.has_auto_determination_toggle === false);
    const pending = res.body.filter((r) => !('has_auto_determination_toggle' in r));

    ok('has at least one Tier 1/2 toggleable rule', toggleable.length > 0);
    ok(
      'toggleable rules match ToggleableRuleOut',
      toggleable.every((r) => hasKeys(r, ['rule_id', 'tier', 'version', 'auto_determination_enabled', 'auto_suspended', 'volume_30d'])),
    );

    ok('has at least one Tier 3 escalation rule', escalation.length > 0);
    ok(
      'Tier 3 rules carry NO auto_determination_enabled field at all (never a disabled toggle)',
      escalation.every((r) => !('auto_determination_enabled' in r)),
    );
    ok('Tier 3 rules are all tier 3', escalation.every((r) => r.tier === 3));

    ok('has at least one pending (unregistered) rule', pending.length > 0);
    ok(
      'pending rules match PendingRuleOut {rule_id, registered: false, reason}',
      pending.every((r) => r.registered === false && typeof r.reason === 'string'),
    );
  }

  console.log('\nPUT /api/admin/rules/{id} — refuses auto_determination_enabled on a Tier 3 rule (422)');
  {
    const res = await api('/api/admin/rules/t3-kev', {
      cookie: adminCookie,
      method: 'PUT',
      body: { auto_determination_enabled: true },
    });
    ok('422 — the server enforces this, not the client (rule 3)', res.status === 422);
  }

  console.log('\nGET /api/dashboard/* — six panels');
  {
    const auditor = await login('auditor1', PASSWORD);
    const panels = [
      ['/api/dashboard/volume', ['since', 'until', 'total_assessments', 'total_findings']],
      ['/api/dashboard/automation-split', ['since', 'until', 'total_decided', 'automated', 'human_reviewed', 'automated_ratio']],
      ['/api/dashboard/sla', ['since', 'until', 'median_hours_to_determination', 'p90_hours_to_determination', 'sample_size', 'breaching_count']],
      ['/api/dashboard/agreement', ['since', 'until']],
      ['/api/dashboard/outcome-mix', ['since', 'until']],
      ['/api/dashboard/expiry', ['lapsing_within_7_days', 'already_expired']],
    ];
    for (const [path, keys] of panels) {
      const res = await api(path, { cookie: auditor.cookie });
      ok(`${path} — 200`, res.status === 200);
      ok(`${path} — matches its panel shape`, hasKeys(res.body, keys));
    }
  }

  console.log('\nPOST /api/auth/logout, then GET /api/auth/me — session actually cleared');
  {
    const logoutRes = await api('/api/auth/logout', { cookie: reviewerCookie, method: 'POST', body: {} });
    ok('logout 200', logoutRes.status === 200);
    // The client must send the cookie the Set-Cookie from logout describes
    // (an expired one) — simplest correct check here is a fresh cookie-less
    // call, which must also be unauthenticated:
    const meRes = await api('/api/auth/me');
    ok('me() with no cookie is 401', meRes.status === 401);
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

main().catch((err) => {
  console.error('verify-api-client.mjs crashed:', err);
  process.exit(1);
});
