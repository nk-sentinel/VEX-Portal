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
is logging in. ``authenticate`` binds directly, using the caller's own
password, then reuses that same bound connection to read its own
``memberOf`` attribute — AD conventionally lets an authenticated user read
that about itself, so no second credential is needed for the group lookup
either.

**The bind DN shape is configurable, not hardcoded** — ``app/config.py``'s
``ldap_bind_dn_template`` (e.g. ``uid={username},{base_dn}`` or
``{username}@example.com`` for AD UPN binds). Left unset, this falls back to
``uid={username},{base_dn}``, which is **an assumption, not a fact confirmed
against a real directory** (there is no AD reachable from this host to
confirm it against) — a real AD tree that keys entries by
``sAMAccountName``, uses a UPN, or nests users under a deeper OU will need
``ldap_bind_dn_template`` set explicitly. See the Task 1-3 report's
"verify at work" list.

**Group-to-role mapping is config-driven and closed.** Every ``Role`` value
has a corresponding ``ldap_group_*`` setting in ``app/config.py``
(``ldap_group_{requester,reviewer,approver,auditor,risk_manager,admin}``);
``tests/auth/test_ldap.py``'s ``test_every_role_has_a_configured_ldap_group_mapping``
iterates ``Role`` and asserts each one is covered, specifically so a role
added later without a matching setting fails loudly here rather than
silently becoming unreachable over LDAP. A ``memberOf`` value with no
configured mapping contributes no role, never a default one — deliberately:
a user who matches no group should hold nothing, not something guessed.

**A rejected credential and an unreachable/malformed directory are
different failures, distinguished by type, not just by log message.** A
directory that responds and says "no" (wrong password, unknown user, a
disabled account) returns ``None`` from :meth:`authenticate` — the same
"this credential did not check out" contract every ``AuthProvider`` shares.
Anything else going wrong while getting that answer — the server cannot be
reached, the TLS handshake fails, the response cannot be parsed, a
misconfigured DN template — raises :class:`LdapUnavailable` instead of
quietly becoming the same ``None`` a wrong password would. Conflating the
two would mean a downed AD server or a bad ``LDAP_URL`` looks, from the
outside, identical to "this one person typed their password wrong" — exactly
the distinction someone debugging a work outage at an unhelpful hour needs
the system to have kept for them.
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


class LdapUnavailable(Exception):
    """The directory could not be reached, bound to, queried, or parsed —
    a connectivity or configuration problem, distinct from a credential the
    directory examined and rejected (which is ``None``, not this). See this
    module's docstring.
    """


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
        # a user who matches no group should hold nothing, not a default.
        self._group_roles: dict[str, Role] = {
            group: role
            for group, role in (
                (settings.ldap_group_requester, Role.REQUESTER),
                (settings.ldap_group_reviewer, Role.REVIEWER),
                (settings.ldap_group_approver, Role.APPROVER),
                (settings.ldap_group_auditor, Role.AUDITOR),
                (settings.ldap_group_risk_manager, Role.RISK_MANAGER),
                (settings.ldap_group_admin, Role.ADMIN),
            )
            if group
        }

    async def authenticate(self, username: str, password: str) -> AuthenticatedUser | None:
        return await asyncio.to_thread(self._authenticate_sync, username, password)

    def _bind_dn(self, username: str) -> str:
        """The DN to bind as for ``username`` — see this module's docstring
        on why the fallback is an assumption, not a confirmed fact.
        """
        template = self._settings.ldap_bind_dn_template
        if not template:
            return f"uid={username},{self._settings.ldap_base_dn}"
        try:
            return template.format(username=username, base_dn=self._settings.ldap_base_dn)
        except (KeyError, IndexError) as exc:
            # A malformed template (an unknown {placeholder}) is a config
            # problem, not a rejected credential — same bucket as a
            # directory that cannot be reached.
            raise LdapUnavailable(f"ldap_bind_dn_template is malformed: {exc}") from exc

    def _authenticate_sync(self, username: str, password: str) -> AuthenticatedUser | None:
        if not password:
            # ldap3 treats an empty simple-bind password as an anonymous
            # bind, which some directories accept outright — never let an
            # empty password "succeed" as this user.
            return None

        user_dn = self._bind_dn(username)
        connection: Connection | None = None
        try:
            server = Server(self._settings.ldap_url)
            connection = self._connection_factory(server, user_dn, password)
            if not connection.bind():
                # The directory answered and said no: wrong password,
                # unknown user, or a disabled account. This is the ordinary
                # AuthProvider "did not check out" contract, not
                # LdapUnavailable — the directory is fine, this credential
                # is not.
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
        except LDAPException as exc:
            # Anything from ldap3 itself — socket/TLS failure, a malformed
            # response, an unreachable server — is a directory/config
            # problem, never silently folded into "wrong password". See
            # this module's docstring.
            raise LdapUnavailable(
                f"could not reach, bind to, or query the LDAP directory: {exc}"
            ) from exc
        finally:
            if connection is not None and connection.bound:
                connection.unbind()


__all__ = ["LdapAuthProvider", "LdapUnavailable"]
