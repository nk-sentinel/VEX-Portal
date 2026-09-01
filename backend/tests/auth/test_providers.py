"""Tests for `app/auth/providers.py`'s `get_auth_provider` factory."""

from __future__ import annotations

import pytest

from app.auth.ldap import LdapAuthProvider
from app.auth.local import LocalAuthProvider
from app.auth.providers import get_auth_provider
from app.config import AuthProviderKind, Settings


@pytest.mark.asyncio
async def test_defaults_to_local_so_a_missing_env_var_never_locks_everyone_out(session):
    settings = Settings(_env_file=None)
    assert settings.auth_provider is AuthProviderKind.LOCAL

    assert isinstance(get_auth_provider(settings, session), LocalAuthProvider)


@pytest.mark.asyncio
async def test_ldap_mode_builds_the_ldap_provider(session):
    settings = Settings(
        _env_file=None, auth_provider="ldap", ldap_url="ldap://example.invalid", ldap_base_dn="dc=x"
    )

    assert isinstance(get_auth_provider(settings, session), LdapAuthProvider)


@pytest.mark.asyncio
async def test_a_none_settings_argument_falls_back_to_get_settings(session, monkeypatch):
    monkeypatch.setenv("AUTH_PROVIDER", "local")
    from app.config import get_settings

    get_settings.cache_clear()
    try:
        assert isinstance(get_auth_provider(None, session), LocalAuthProvider)
    finally:
        get_settings.cache_clear()
