"""Tests for `app/auth/ldap.py` — the LDAP/AD auth provider.

**No AD is reachable from this host.** These tests exercise
`LdapAuthProvider.authenticate` against `ldap3`'s own `MOCK_SYNC` client
strategy, chosen over a hand-rolled fake connection because it keeps the
provider's real bind-then-search-self code path completely intact: a setup
connection populates fixture entries, and a *second, independent*
`Connection` — built via the same `connection_factory` seam
`LdapAuthProvider` uses in production — binds and searches against that
same in-memory directory. `MOCK_SYNC` keeps its DIT on the shared
`ldap3.Server` object rather than per-connection (confirmed empirically
before writing this suite), which is what makes that two-connection setup
work at all.
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest
from ldap3 import MOCK_SYNC, Connection, Server
from ldap3.core.exceptions import LDAPSocketOpenError

from app.auth.ldap import ConnectionFactory, LdapAuthProvider, LdapUnavailable
from app.config import Settings
from app.repos.models import Role

_BASE_DN = "ou=users,dc=vex,dc=local"
_REQUESTER_GROUP = "cn=vex-requesters,ou=groups,dc=vex,dc=local"
_REVIEWER_GROUP = "cn=vex-reviewers,ou=groups,dc=vex,dc=local"
_APPROVER_GROUP = "cn=vex-approvers,ou=groups,dc=vex,dc=local"
_AUDITOR_GROUP = "cn=vex-auditors,ou=groups,dc=vex,dc=local"
_RISK_MANAGER_GROUP = "cn=vex-risk-managers,ou=groups,dc=vex,dc=local"
_ADMIN_GROUP = "cn=vex-admins,ou=groups,dc=vex,dc=local"
#: Stands in for a real AD group with no configured mapping.
_UNMAPPED_GROUP = "cn=some-other-ad-group,ou=groups,dc=vex,dc=local"

_ALL_CONFIGURED_GROUPS = {
    Role.REQUESTER: _REQUESTER_GROUP,
    Role.REVIEWER: _REVIEWER_GROUP,
    Role.APPROVER: _APPROVER_GROUP,
    Role.AUDITOR: _AUDITOR_GROUP,
    Role.RISK_MANAGER: _RISK_MANAGER_GROUP,
    Role.ADMIN: _ADMIN_GROUP,
}


def _settings(**overrides: object) -> Settings:
    defaults: dict[str, object] = {
        "_env_file": None,
        "ldap_url": "ldap://vex-mock.invalid",
        "ldap_base_dn": _BASE_DN,
        "ldap_group_requester": _REQUESTER_GROUP,
        "ldap_group_reviewer": _REVIEWER_GROUP,
        "ldap_group_approver": _APPROVER_GROUP,
        "ldap_group_auditor": _AUDITOR_GROUP,
        "ldap_group_risk_manager": _RISK_MANAGER_GROUP,
        "ldap_group_admin": _ADMIN_GROUP,
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


def _mock_directory() -> Server:
    """A `Server` with one in-memory DIT, populated via a throwaway admin
    connection using `ldap3`'s MOCK_SYNC strategy.
    """
    server = Server("vex-ldap-mock")
    setup = Connection(
        server, user="cn=admin", password="admin-only-for-fixture-setup", client_strategy=MOCK_SYNC
    )
    setup.bind()
    setup.strategy.add_entry(
        f"uid=alice,{_BASE_DN}",
        {
            "objectClass": "person",
            "uid": "alice",
            "userPassword": "alice-password",
            "memberOf": [_REVIEWER_GROUP, _APPROVER_GROUP],
        },
    )
    setup.strategy.add_entry(
        f"uid=bob,{_BASE_DN}",
        {
            "objectClass": "person",
            "uid": "bob",
            "userPassword": "bob-password",
            "memberOf": [_UNMAPPED_GROUP],
        },
    )
    setup.strategy.add_entry(
        f"uid=carol,{_BASE_DN}",
        {
            "objectClass": "person",
            "uid": "carol",
            "userPassword": "carol-password",
            "memberOf": [],
        },
    )
    setup.strategy.add_entry(
        f"uid=dana,{_BASE_DN}",
        {
            "objectClass": "person",
            "uid": "dana",
            "userPassword": "dana-password",
            # Every configured group at once — the six-role coverage check.
            "memberOf": list(_ALL_CONFIGURED_GROUPS.values()),
        },
    )
    setup.strategy.add_entry(
        "uid=erin,dc=upn,dc=vex,dc=local",
        {
            "objectClass": "person",
            "uid": "erin",
            "userPassword": "erin-password",
            "memberOf": [],
        },
    )
    return server


def _factory_for(server: Server) -> ConnectionFactory:
    """A `connection_factory` matching `LdapAuthProvider`'s own seam,
    substituting the shared mock `Server` for the real one `settings.ldap_url`
    would otherwise point at.
    """

    def factory(_server: Server, user_dn: str, password: str) -> Connection:
        return Connection(server, user=user_dn, password=password, client_strategy=MOCK_SYNC)

    return factory


def _provider(server: Server, **settings_overrides: object) -> LdapAuthProvider:
    return LdapAuthProvider(
        _settings(**settings_overrides), connection_factory=_factory_for(server)
    )


def _roles(values: Iterable[Role]) -> frozenset[Role]:
    return frozenset(values)


@pytest.mark.asyncio
async def test_correct_password_authenticates_and_maps_multiple_groups():
    provider = _provider(_mock_directory())

    result = await provider.authenticate("alice", "alice-password")

    assert result is not None
    assert result.username == "alice"
    assert result.roles == _roles({Role.REVIEWER, Role.APPROVER})


@pytest.mark.asyncio
async def test_wrong_password_returns_none():
    provider = _provider(_mock_directory())

    assert await provider.authenticate("alice", "not-the-password") is None


@pytest.mark.asyncio
async def test_unknown_username_returns_none():
    provider = _provider(_mock_directory())

    assert await provider.authenticate("nobody", "whatever") is None


@pytest.mark.asyncio
async def test_unmapped_group_yields_no_role_rather_than_a_default_one():
    # bob's only group membership has no configured ldap_group_* mapping —
    # the result must be zero roles, never a fallback role.
    provider = _provider(_mock_directory())

    result = await provider.authenticate("bob", "bob-password")

    assert result is not None
    assert result.roles == frozenset()


@pytest.mark.asyncio
async def test_no_group_membership_at_all_yields_no_role():
    provider = _provider(_mock_directory())

    result = await provider.authenticate("carol", "carol-password")

    assert result is not None
    assert result.roles == frozenset()


@pytest.mark.asyncio
async def test_empty_password_is_rejected_without_binding():
    # ldap3 treats an empty simple-bind password as an anonymous bind on
    # some directories — never let that "succeed" as a real user.
    provider = _provider(_mock_directory())

    assert await provider.authenticate("alice", "") is None


# --- Every Role is reachable over LDAP -------------------------------------


def test_every_role_has_a_configured_ldap_group_setting():
    # The guard that would have caught the original gap: a Role added later
    # without a matching ldap_group_* setting is silently unreachable over
    # LDAP, and nothing else here would fail. Iterate the enum, not a
    # hardcoded list, so a new member is covered automatically.
    settings = _settings()
    for role in Role:
        attr = f"ldap_group_{role.value}"
        assert hasattr(settings, attr), f"no ldap_group_* setting for Role.{role.name} ({attr})"
        assert getattr(settings, attr), f"{attr} is configured but empty in this test's settings"


@pytest.mark.asyncio
async def test_a_user_in_every_configured_group_holds_every_role():
    # Functional companion to the settings-coverage check above: proves the
    # six settings are actually wired into the group->role mapping, not
    # merely present on Settings.
    provider = _provider(_mock_directory())

    result = await provider.authenticate("dana", "dana-password")

    assert result is not None
    assert result.roles == frozenset(Role)


# --- Bind DN template --------------------------------------------------------


@pytest.mark.asyncio
async def test_default_bind_dn_falls_back_to_uid_equals_username():
    # No ldap_bind_dn_template configured -> the documented fallback shape.
    provider = _provider(_mock_directory())

    result = await provider.authenticate("alice", "alice-password")

    assert result is not None


@pytest.mark.asyncio
async def test_configured_bind_dn_template_is_used_instead_of_the_fallback():
    # erin's fixture entry is NOT at uid=erin,<base_dn> — only reachable if
    # ldap_bind_dn_template is actually honoured rather than the fallback.
    server = _mock_directory()
    provider = _provider(
        server, ldap_bind_dn_template="uid={username},dc=upn,dc=vex,dc=local"
    )

    result = await provider.authenticate("erin", "erin-password")

    assert result is not None
    assert result.username == "erin"


@pytest.mark.asyncio
async def test_a_malformed_bind_dn_template_raises_ldap_unavailable_not_a_silent_miss():
    server = _mock_directory()
    provider = _provider(server, ldap_bind_dn_template="uid={not_a_real_placeholder}")

    with pytest.raises(LdapUnavailable):
        await provider.authenticate("alice", "alice-password")


# --- Directory-unavailable vs credential-rejected are different failures ---


@pytest.mark.asyncio
async def test_an_unreachable_directory_raises_ldap_unavailable_not_none():
    # A rejected credential and a directory the code cannot even talk to
    # must not look the same to a caller — the former is a 401 (login.py),
    # the latter is a 503. Simulate the latter with a connection factory
    # that fails the way a real unreachable server does.
    def broken_factory(_server: Server, _user_dn: str, _password: str) -> Connection:
        raise LDAPSocketOpenError("simulated: could not open a connection to the directory")

    provider = LdapAuthProvider(_settings(), connection_factory=broken_factory)

    with pytest.raises(LdapUnavailable):
        await provider.authenticate("alice", "alice-password")


@pytest.mark.asyncio
async def test_ldap_unavailable_message_never_contains_the_password():
    def broken_factory(_server: Server, _user_dn: str, _password: str) -> Connection:
        raise LDAPSocketOpenError("simulated failure")

    provider = LdapAuthProvider(_settings(), connection_factory=broken_factory)
    secret_password = "definitely-not-logged"  # noqa: S105 - test fixture

    with pytest.raises(LdapUnavailable) as excinfo:
        await provider.authenticate("alice", secret_password)

    assert secret_password not in str(excinfo.value)


@pytest.mark.asyncio
async def test_a_rejected_credential_against_a_reachable_directory_is_still_none():
    # Contrast case for the two tests above: the directory IS reachable
    # here (the mock answers), it just says no — that must stay None, not
    # LdapUnavailable.
    provider = _provider(_mock_directory())

    assert await provider.authenticate("alice", "wrong-password") is None
