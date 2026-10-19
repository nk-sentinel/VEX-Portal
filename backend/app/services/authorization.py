"""Capability-based authorisation: what a role is allowed to do, and the one
rule no role — including one held alongside APPROVER — is allowed to
override.

**Capabilities, not roles, at the call site.** ``app/api/deps.py``'s
``requires(Capability)`` dependency, and every future route that guards an
action, check a ``Capability`` — never a ``Role`` directly. The mapping
below is the only place a role/capability relationship is written down, so
changing which role may do something is a one-line edit here, not a sweep
through every route that happens to care.

**ADMIN holds every capability.** ``FULL_ACCESS_ROLES`` is folded into every
entry of :data:`CAPABILITY_ROLES` below, rather than listed capability by
capability, so a capability added later cannot accidentally omit it — the
failure mode would be an administrator who cannot administer one new thing,
discovered only when someone tries.

One consequence worth stating rather than leaving implicit: an
administrator can both set a rule's thresholds and commit a determination,
so the "someone else configured the bar I am approving against" control
does not hold for that role. Separation of duties still does (see below) —
an admin who raised an assessment cannot commit it — but the configure-then-
approve path is open to anyone holding ADMIN, and the audit log is what
makes it visible after the fact rather than preventing it.

**Separation of duties is enforced here, in the service layer, and tested
here — not at the route.** A route-only check is decoration: it protects
exactly the one call site it sits in front of, and is bypassed the moment a
second route (or a script, or a future admin tool) reaches the same
underlying service. ``assert_may_commit_own_determination`` is what
``app/services/determination.py``'s commit path (wired up in a later task)
must call before doing anything else — a requester may never commit a
determination on their own assessment, even while also holding APPROVER,
because holding two roles at once is exactly the scenario separation of
duties exists to catch.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from app.repos.models import Assessment, Role


class Capability(StrEnum):
    """One action the API can be asked to perform, independent of who may
    perform it — see the module docstring for why the call site checks
    this, never a ``Role``.
    """

    RAISE_ASSESSMENT = "raise_assessment"
    VIEW_QUEUE = "view_queue"
    RECOMMEND_DETERMINATION = "recommend_determination"
    COMMIT_DETERMINATION = "commit_determination"
    VIEW_DASHBOARD = "view_dashboard"
    VIEW_RISK_ACCEPTANCE = "view_risk_acceptance"
    #: Setting the hand-off status (Awaiting hand-off / With risk manager /
    #: Accepted / Rejected) on a risk-acceptance row — added in Task 6,
    #: distinct from ``VIEW_RISK_ACCEPTANCE`` on purpose: an auditor can see
    #: the risk-acceptance queue (that capability) but must not be able to
    #: mutate its status — an auditor is a read-only role by definition, and
    #: folding a write action into the view capability would quietly grant
    #: one anyway. See ``docs/design/ui-spec.md`` screen 8: "Status is
    #: manually set by the risk manager."
    MANAGE_RISK_ACCEPTANCE = "manage_risk_acceptance"
    MANAGE_RULES = "manage_rules"


#: Roles that hold every capability, present or future — see the module
#: docstring. Folded into every entry of :data:`CAPABILITY_ROLES` so a
#: capability added later includes them without a second edit.
FULL_ACCESS_ROLES: frozenset[Role] = frozenset({Role.ADMIN})

#: Which roles grant each capability *in addition to* FULL_ACCESS_ROLES.
#: Not read directly by anything outside this module — ``CAPABILITY_ROLES``
#: below is the resolved table every caller uses.
_GRANTS: dict[Capability, frozenset[Role]] = {
    Capability.RAISE_ASSESSMENT: frozenset({Role.REQUESTER}),
    Capability.VIEW_QUEUE: frozenset({Role.REVIEWER, Role.APPROVER, Role.AUDITOR}),
    Capability.RECOMMEND_DETERMINATION: frozenset({Role.REVIEWER, Role.APPROVER}),
    Capability.COMMIT_DETERMINATION: frozenset({Role.APPROVER}),
    Capability.VIEW_DASHBOARD: frozenset({Role.AUDITOR}),
    Capability.VIEW_RISK_ACCEPTANCE: frozenset({Role.RISK_MANAGER, Role.AUDITOR}),
    Capability.MANAGE_RISK_ACCEPTANCE: frozenset({Role.RISK_MANAGER}),
    Capability.MANAGE_RULES: frozenset(),
}

#: The single source of truth for which roles grant which capability. See
#: the module docstring: this is the one place that changes when a role's
#: permissions change. Built from :data:`_GRANTS` with
#: :data:`FULL_ACCESS_ROLES` added to every entry, and keyed over
#: ``Capability`` itself so a capability missing from ``_GRANTS`` fails at
#: import rather than silently granting nothing.
CAPABILITY_ROLES: dict[Capability, frozenset[Role]] = {
    capability: _GRANTS[capability] | FULL_ACCESS_ROLES for capability in Capability
}


def roles_for(capability: Capability) -> frozenset[Role]:
    """Which roles grant ``capability`` — exactly the table in the plan
    document, read back out of :data:`CAPABILITY_ROLES`.
    """
    return CAPABILITY_ROLES[capability]


def has_capability(roles: Iterable[Role], capability: Capability) -> bool:
    """Whether holding any of ``roles`` grants ``capability``."""
    return not CAPABILITY_ROLES[capability].isdisjoint(roles)


class SeparationOfDutiesError(PermissionError):
    """A requester attempted to commit a determination on their own
    assessment. A ``PermissionError`` subclass rather than a bare
    ``Exception``, mirroring how ``app/repos/models.py``'s audit-log guard
    signals an authorisation failure, not a data problem.
    """


def assert_may_commit_own_determination(*, assessment: Assessment, actor_username: str) -> None:
    """A requester may never approve their own assessment.

    Enforced against ``Assessment.requester`` — the username that raised the
    assessment — compared to ``actor_username``, the identity of whoever is
    about to commit a determination against it. Deliberately independent of
    role: this check runs regardless of whether ``actor_username`` also
    holds APPROVER, because that is exactly the case separation of duties
    exists to catch. ``app/api/deps.py``'s ``requires(Capability.COMMIT_DETERMINATION)``
    only confirms the actor holds a role that *can* commit determinations in
    general; it says nothing about *this* assessment, which is what makes
    this a service-layer check rather than something the role/capability
    table above could ever express.

    Raises:
        SeparationOfDutiesError: ``actor_username`` raised ``assessment``.
    """
    if assessment.requester == actor_username:
        raise SeparationOfDutiesError(
            "a requester cannot commit a determination on their own assessment"
        )


__all__ = [
    "CAPABILITY_ROLES",
    "FULL_ACCESS_ROLES",
    "Capability",
    "SeparationOfDutiesError",
    "assert_may_commit_own_determination",
    "has_capability",
    "roles_for",
]
