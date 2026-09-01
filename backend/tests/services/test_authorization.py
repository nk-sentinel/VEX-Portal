"""Tests for `app/services/authorization.py` — the capability table and the
separation-of-duties check.

**The separation-of-duties tests call `assert_may_commit_own_determination`
directly** — the service function itself, never through a route. A
route-only check protects exactly the one call site it sits in front of; it
proves nothing about whether a second route (or a script, or a future admin
tool) reaching the same underlying service is protected too. This is the
layer the plan document requires the rule be enforced and tested at, and
the requester-holding-APPROVER case below is exactly the scenario a
route-level-only check would miss.
"""

from __future__ import annotations

import pytest

from app.repos.models import Assessment, Role
from app.services.authorization import (
    CAPABILITY_ROLES,
    Capability,
    SeparationOfDutiesError,
    assert_may_commit_own_determination,
    has_capability,
    roles_for,
)

#: The RBAC table from the plan document, restated here as the expected
#: value every test below checks the real mapping against — if a future
#: edit to CAPABILITY_ROLES drifts from this table, these tests catch it.
_EXPECTED: dict[Capability, set[Role]] = {
    Capability.RAISE_ASSESSMENT: {Role.REQUESTER},
    Capability.VIEW_QUEUE: {Role.REVIEWER, Role.APPROVER, Role.AUDITOR},
    Capability.RECOMMEND_DETERMINATION: {Role.REVIEWER, Role.APPROVER},
    Capability.COMMIT_DETERMINATION: {Role.APPROVER},
    Capability.VIEW_DASHBOARD: {Role.AUDITOR, Role.ADMIN},
    Capability.VIEW_RISK_ACCEPTANCE: {Role.RISK_MANAGER, Role.AUDITOR},
    Capability.MANAGE_RISK_ACCEPTANCE: {Role.RISK_MANAGER},
    Capability.MANAGE_RULES: {Role.ADMIN},
}


def test_every_capability_the_table_defines_is_mapped():
    assert set(_EXPECTED) == set(Capability)
    for capability in Capability:
        assert capability in CAPABILITY_ROLES


@pytest.mark.parametrize("capability", list(Capability))
def test_each_capability_admits_exactly_its_roles_and_rejects_the_rest(capability):
    expected_roles = _EXPECTED[capability]
    for role in Role:
        admitted = has_capability({role}, capability)
        assert admitted == (role in expected_roles), (
            f"{capability.value} incorrectly "
            f"{'admitted' if admitted else 'rejected'} {role.value}"
        )


@pytest.mark.parametrize("capability", list(Capability))
def test_roles_for_matches_the_plan_documents_table(capability):
    assert roles_for(capability) == frozenset(_EXPECTED[capability])


def test_holding_any_one_admitting_role_among_several_held_is_enough():
    assert has_capability({Role.REQUESTER, Role.AUDITOR}, Capability.VIEW_QUEUE)


def test_holding_only_non_admitting_roles_is_rejected():
    assert not has_capability({Role.REQUESTER}, Capability.VIEW_QUEUE)


def test_holding_no_roles_at_all_is_rejected_by_every_capability():
    for capability in Capability:
        assert not has_capability(frozenset(), capability)


def test_an_auditor_can_view_risk_acceptance_but_not_manage_it():
    # An auditor is read-only by definition — VIEW_RISK_ACCEPTANCE and
    # MANAGE_RISK_ACCEPTANCE are deliberately different capabilities so a
    # write action can never ride along with the view one.
    assert has_capability({Role.AUDITOR}, Capability.VIEW_RISK_ACCEPTANCE)
    assert not has_capability({Role.AUDITOR}, Capability.MANAGE_RISK_ACCEPTANCE)


# --- Separation of duties ---------------------------------------------------


def _assessment(requester: str) -> Assessment:
    return Assessment(application_id="payments-api", report_id="r1", requester=requester)


def test_a_requester_cannot_commit_a_determination_on_their_own_assessment():
    assessment = _assessment("j.doe")

    with pytest.raises(SeparationOfDutiesError):
        assert_may_commit_own_determination(assessment=assessment, actor_username="j.doe")


def test_this_holds_even_when_the_requester_also_holds_approver():
    # The capability table alone would admit j.doe here: they hold
    # APPROVER, which is all requires(Capability.COMMIT_DETERMINATION) ever
    # checks. This is exactly the gap separation of duties exists to catch
    # — holding the role is necessary but never sufficient for THIS
    # assessment.
    assessment = _assessment("j.doe")
    assert has_capability({Role.APPROVER}, Capability.COMMIT_DETERMINATION)

    with pytest.raises(SeparationOfDutiesError, match="own assessment"):
        assert_may_commit_own_determination(assessment=assessment, actor_username="j.doe")


def test_a_different_approver_may_commit_the_determination():
    assessment = _assessment("j.doe")

    # No exception raised is the assertion.
    assert_may_commit_own_determination(assessment=assessment, actor_username="a.reviewer")


def test_username_comparison_is_exact_not_case_insensitive_by_accident():
    # Pin the actual (deliberately simple) comparison rather than leaving it
    # to whatever str.__eq__ happens to do — a case-insensitive match would
    # be a different, larger design decision (canonicalising usernames) not
    # made here.
    assessment = _assessment("J.Doe")

    assert_may_commit_own_determination(assessment=assessment, actor_username="j.doe")
