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

from app.auth.ldap import ConnectionFactory, LdapAuthProvider
from app.config import Settings
from app.repos.models import Role

_BASE_DN = "ou=users,dc=vex,dc=local"
_REVIEWER_GROUP = "cn=vex-reviewers,ou=groups,dc=vex,dc=local"
_APPROVER_GROUP = "cn=vex-approvers,ou=groups,dc=vex,dc=local"
#: Stands in for a real AD group with no configured mapping — notably,
#: there is no `ldap_group_requester`/`ldap_group_admin` setting in
#: app/config.py at all, so a REQUESTER or ADMIN group would land here too.
_UNMAPPED_GROUP = "cn=some-other-ad-group,ou=groups,dc=vex,dc=local"


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        ldap_url="ldap://vex-mock.invalid",
        ldap_base_dn=_BASE_DN,
        ldap_group_reviewer=_REVIEWER_GROUP,
        ldap_group_approver=_APPROVER_GROUP,
        ldap_group_auditor="",
        ldap_group_risk_manager="",
    )


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
    return server


def _factory_for(server: Server) -> ConnectionFactory:
    """A `connection_factory` matching `LdapAuthProvider`'s own seam,
    substituting the shared mock `Server` for the real one `settings.ldap_url`
    would otherwise point at.
    """

    def factory(_server: Server, user_dn: str, password: str) -> Connection:
        return Connection(server, user=user_dn, password=password, client_strategy=MOCK_SYNC)

    return factory


def _provider(server: Server) -> LdapAuthProvider:
    return LdapAuthProvider(_settings(), connection_factory=_factory_for(server))


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
