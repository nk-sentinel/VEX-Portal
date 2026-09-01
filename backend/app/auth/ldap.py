"""LDAP/AD-backed authentication — the work-environment provider.

**No AD is reachable from this host**, so this module is exercised in tests
against ``ldap3``'s own ``MOCK_SYNC`` client strategy rather than a live
directory or a hand-rolled fake connection — see the Task 1-3 report for why
that was chosen over injecting a fake connection object: ``MOCK_SYNC``
keeps its in-memory directory on the shared ``ldap3.Server`` instance (not
per-``Connection``), so a test can populate fixture entries on one
connection and then exercise :meth:`LdapAuthProvider.authenticate`'s own
bind-and-search flow, unmodified, against a second connection that shares
the same ``Server`` — the real code path runs end to end, not a stand-in for
it.

**The bind is direct, not search-then-bind.** ``app/config.py`` carries no
service/bind account for LDAP (only ``ldap_url`` and ``ldap_base_dn``), so
there is no credential available to search the directory before knowing who
is logging in. ``authenticate`` binds as
``uid=<username>,<ldap_base_dn>`` directly, using the caller's own
password, then reuses that same bound connection to read its own
``memberOf`` attribute — AD conventionally lets an authenticated user read
that about itself, so no second credential is needed for the group lookup
either. **This DN shape is an assumption, not a fact confirmed against a
real directory** — flagged explicitly in the Task 1-3 report. A real AD tree
that keys entries by ``sAMAccountName``, uses a UPN
(``user@domain``), or nests users under a deeper OU than a flat child of
``ldap_base_dn`` will need this template revisited; nothing else in this
module depends on the shape being right beyond this one f-string.

**Group-to-role mapping is config-driven and closed.** Only four of the six
``Role`` values have a configured LDAP group
(``ldap_group_{reviewer,approver,auditor,risk_manager}`` in
``app/config.py``) — there is no ``ldap_group_requester`` or
``ldap_group_admin`` setting. A ``memberOf`` value with no configured
mapping — which, as configured today, includes any group standing in for
REQUESTER or ADMIN — contributes no role, never a default one. **This means
an LDAP-authenticated user can never hold REQUESTER or ADMIN as configured
today.** That may be intentional (Requester open to every authenticated
user regardless of group; Admin reserved to local break-glass accounts) or
may be a gap in ``app/config.py``'s settings — flagged in the Task 1-3
report as context the brief did not supply data for, not resolved here by
guessing a default.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from ldap3 import BASE, Connection, Server
from ldap3.core.exceptions import LDAPException

from app.auth.providers import AuthenticatedUser
from app.config import Settings
from app.repos.models import Role

#: Builds the ``Connection`` a bind attempt runs over. The real, network
#: default; tests inject one that constructs an ``ldap3`` MOCK_SYNC
#: connection instead (see this module's docstring), so nothing here needs
#: a reachable AD.
ConnectionFactory = Callable[[Server, str, str], Connection]


def _default_connection_factory(server: Server, user_dn: str, password: str) -> Connection:
    return Connection(server, user=user_dn, password=password)


class LdapAuthProvider:
    """Authenticates by binding directly as the user against LDAP/AD.

    ``authenticate`` runs the network I/O in a worker thread
    (``asyncio.to_thread``) — ``ldap3``'s synchronous strategies (including
    ``MOCK_SYNC``, used in tests) block the calling thread, and this
    provider is awaited from an async request handler that must not stall
    the event loop for the duration of a directory round trip.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        connection_factory: ConnectionFactory = _default_connection_factory,
    ) -> None:
        self._settings = settings
        self._connection_factory = connection_factory
        # Built once at construction, not per call: a group with no
        # configured mapping (falsy setting value) is never a lookup key —
        # see this module's docstring on why REQUESTER/ADMIN are absent.
        self._group_roles: dict[str, Role] = {
            group: role
            for group, role in (
                (settings.ldap_group_reviewer, Role.REVIEWER),
                (settings.ldap_group_approver, Role.APPROVER),
                (settings.ldap_group_auditor, Role.AUDITOR),
                (settings.ldap_group_risk_manager, Role.RISK_MANAGER),
            )
            if group
        }

    async def authenticate(self, username: str, password: str) -> AuthenticatedUser | None:
        return await asyncio.to_thread(self._authenticate_sync, username, password)

    def _authenticate_sync(self, username: str, password: str) -> AuthenticatedUser | None:
        if not password:
            # ldap3 treats an empty simple-bind password as an anonymous
            # bind, which some directories accept outright — never let an
            # empty password "succeed" as this user.
            return None

        user_dn = f"uid={username},{self._settings.ldap_base_dn}"
        server = Server(self._settings.ldap_url)
        connection = self._connection_factory(server, user_dn, password)
        try:
            if not connection.bind():
                return None
            connection.search(
                user_dn, "(objectClass=*)", search_scope=BASE, attributes=["memberOf"]
            )
            groups: list[str] = (
                list(connection.entries[0].memberOf.values) if connection.entries else []
            )
            roles = frozenset(
                self._group_roles[group] for group in groups if group in self._group_roles
            )
            return AuthenticatedUser(username=username, roles=roles)
        except LDAPException:
            return None
        finally:
            if connection.bound:
                connection.unbind()


__all__ = ["LdapAuthProvider"]
