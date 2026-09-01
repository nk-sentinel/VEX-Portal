"""Tests for `app/auth/local.py` — the LOCAL auth provider.

The account-enumeration guard is not tested by measuring wall-clock time
(flaky under any CI load); it asserts the actual mechanism instead:
`PasswordHasher.verify` runs against a real hash for BOTH an unknown
username and a known one with the wrong password. An early return on an
unknown username would show up here as `verify` never being called for that
case — the real bug this guards against, not a timing proxy for it.
"""

from __future__ import annotations

import pytest
from argon2 import PasswordHasher

from app.auth import local as local_module
from app.auth.local import LocalAuthProvider
from app.repos.models import Role, User

_PASSWORD = "correct horse battery staple"  # noqa: S105 - test fixture, not a real credential


class _VerifySpy:
    """Wraps the real hasher and records every `verify()` call.

    `argon2.PasswordHasher` is an immutable (attrs-frozen) object — its own
    `verify` attribute cannot be patched directly (`unittest.mock.patch.object`
    on the instance raises `AttributeError: ... attribute 'verify' is
    read-only`). Swapping out the whole module-level `_hasher` binding in
    `app/auth/local.py` for one of these, via `monkeypatch.setattr`, sidesteps
    that: `authenticate()` looks up `_hasher` fresh from module globals on
    every call, so it sees the spy for the duration of the test and the real
    object again once monkeypatch undoes it.
    """

    def __init__(self, real: PasswordHasher) -> None:
        self._real = real
        self.calls: list[tuple[str, str]] = []

    def verify(self, hash_value: str, password: str) -> bool:
        self.calls.append((hash_value, password))
        return self._real.verify(hash_value, password)


async def _make_user(
    session,
    *,
    username: str = "alice",
    password: str = _PASSWORD,
    roles: tuple[str, ...] = ("reviewer",),
) -> User:
    hasher = PasswordHasher()
    user = User(username=username, password_hash=hasher.hash(password), roles_json=list(roles))
    session.add(user)
    await session.flush()
    return user


@pytest.mark.asyncio
async def test_correct_password_authenticates(session):
    await _make_user(session)
    provider = LocalAuthProvider(session)

    result = await provider.authenticate("alice", _PASSWORD)

    assert result is not None
    assert result.username == "alice"
    assert result.roles == frozenset({Role.REVIEWER})


@pytest.mark.asyncio
async def test_wrong_password_returns_none(session):
    await _make_user(session)
    provider = LocalAuthProvider(session)

    assert await provider.authenticate("alice", "not the password") is None


@pytest.mark.asyncio
async def test_unknown_username_returns_none(session):
    provider = LocalAuthProvider(session)

    assert await provider.authenticate("nobody-such-user", "whatever") is None


@pytest.mark.asyncio
async def test_unknown_username_does_a_real_hash_comparison_rather_than_returning_early(
    session, monkeypatch
):
    spy = _VerifySpy(local_module._hasher)
    monkeypatch.setattr(local_module, "_hasher", spy)
    provider = LocalAuthProvider(session)

    await provider.authenticate("nobody-such-user", "whatever")

    assert len(spy.calls) == 1
    assert spy.calls[0][0] == local_module._DUMMY_HASH


@pytest.mark.asyncio
async def test_known_username_wrong_password_does_exactly_one_hash_comparison_too(
    session, monkeypatch
):
    # Same call count as the unknown-username case above: comparable work
    # either way, which is the whole point of _DUMMY_HASH.
    await _make_user(session)
    spy = _VerifySpy(local_module._hasher)
    monkeypatch.setattr(local_module, "_hasher", spy)
    provider = LocalAuthProvider(session)

    await provider.authenticate("alice", "wrong password")

    assert len(spy.calls) == 1


@pytest.mark.asyncio
async def test_password_hash_never_appears_in_repr(session):
    user = await _make_user(session)

    assert user.password_hash not in repr(user)
    assert _PASSWORD not in repr(user)


@pytest.mark.asyncio
async def test_authenticated_user_carries_no_hash_or_password(session):
    user = await _make_user(session)
    provider = LocalAuthProvider(session)

    result = await provider.authenticate("alice", _PASSWORD)

    assert result is not None
    assert not hasattr(result, "password_hash")
    assert user.password_hash not in repr(result)
    assert _PASSWORD not in repr(result)


@pytest.mark.asyncio
async def test_roles_round_trip_through_the_role_enum(session):
    await _make_user(session, roles=("reviewer", "approver", "admin"))
    provider = LocalAuthProvider(session)

    result = await provider.authenticate("alice", _PASSWORD)

    assert result is not None
    assert result.roles == frozenset({Role.REVIEWER, Role.APPROVER, Role.ADMIN})
