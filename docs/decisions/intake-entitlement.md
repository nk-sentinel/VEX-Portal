# Intake no longer checks Nexus IQ entitlement

**Decided 2026-10-19.** Superseded the per-user-IQ-token open item.

## What changed

`POST /api/assessments` took the requester's `application_id` and refused it with 403
unless it appeared in `IqClient.applications_for_user(...)`. That call, and the
`GET /api/applications` endpoint that populated New Assessment's application dropdown,
are both removed. The form now takes a typed application id.

## Why

The design had app-level entitlement inherited from IQ: call IQ *as the user*, and
`GET /api/v2/applications` returns only what that user may read, so the portal never keeps
a parallel permission model that drifts. That rests on a per-user IQ token.

No such token exists here. Neither auth provider (`app/auth/local.py`, `app/auth/ldap.py`)
issues or stores one, and the portal session carries only a username and portal roles.
`_iq_user_token()` passed the portal **username** as a placeholder, which the fake IQ
ignores entirely. So the check was either a no-op (against the fakes) or — had the service
token been substituted, the tempting fix — an authorisation check against the *service*
account's reach rather than the user's, which is strictly worse than no check because it
looks like one.

## What this gives up

Nothing currently constrains which application a requester may raise an assessment
against. Admission is now the first gate: an application id the service credential cannot
resolve a report for fails the report check with an actionable message.

Before the work deployment, decide whether app-level entitlement is needed at all. If it
is, the mechanism is IQ's User Token feature, and the open questions are unchanged — where
the token lives (session-only vs encrypted at rest; note `app/config.py`'s rule that
secrets come from the environment, never the database) and where it is captured (login vs
a profile page).

`IqHttpClient.applications_for_user` is deliberately **kept**: it is verified against IQ's
real API shape, no route calls it, and deleting it would throw away the only part of this
that was hard to get right.
