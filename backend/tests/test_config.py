import pytest

from app.config import AdapterMode, Settings


def test_defaults_to_fake_adapters_so_a_misconfigured_deploy_cannot_reach_production():
    # Defaulting to REAL would mean a missing env var silently points a dev
    # instance at the live Nexus IQ. Fake is the safe default.
    assert Settings(_env_file=None).adapter_mode is AdapterMode.FAKE


def test_database_url_defaults_to_a_local_sqlite_file():
    assert Settings(_env_file=None).database_url.startswith("sqlite+aiosqlite://")


def test_secrets_are_not_repeated_in_the_string_form():
    # Settings gets logged during startup diagnostics. A token in __repr__
    # would land in logs and in any error report built from them.
    s = Settings(_env_file=None, iq_service_token="super-secret-token")
    assert "super-secret-token" not in repr(s)
    assert "super-secret-token" not in str(s)


def test_real_mode_requires_every_endpoint():
    # Half-configured REAL mode is worse than FAKE: some calls succeed against
    # production while others fail confusingly.
    with pytest.raises(ValueError, match="iq_base_url"):
        Settings(_env_file=None, adapter_mode="real")
