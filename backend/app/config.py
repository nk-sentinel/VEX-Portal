"""Runtime settings.

Two rules shape this module.

Secrets and infrastructure facts come from the environment, never from the
database or an API response: a token stored in the database appears in backups,
on an admin's screen, and in anything built from a settings dump. Behaviour
tunables — thresholds, per-rule toggles — live in the database instead, because
they are decisions the team makes and must be audited.

The adapter mode defaults to FAKE. Defaulting to REAL would mean one missing
environment variable silently points a development instance at the live Nexus IQ
and creates determinations against real applications.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AdapterMode(StrEnum):
    """Which implementation backs every external system."""

    REAL = "real"
    FAKE = "fake"


class AuthProviderKind(StrEnum):
    """Which implementation checks a username/password pair.

    Mirrors ``AdapterMode`` above. Defaults to LOCAL, not LDAP: defaulting to
    LDAP on a machine with no AD reachable means nobody can log in, and the
    failure mode is a confusing connection error rather than an obvious one.
    """

    LOCAL = "local"
    LDAP = "ldap"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", frozen=True
    )

    adapter_mode: AdapterMode = AdapterMode.FAKE
    auth_provider: AuthProviderKind = AuthProviderKind.LOCAL

    database_url: str = "sqlite+aiosqlite:///./data/vex.db"

    iq_base_url: str = ""
    iq_service_user: str = ""
    iq_service_token: SecretStr = SecretStr("")

    jfrog_base_url: str = ""
    jfrog_token: SecretStr = SecretStr("")

    bitbucket_base_url: str = ""
    bitbucket_token: SecretStr = SecretStr("")

    elk_base_url: str = ""
    elk_index: str = "sbom-scans-*"
    elk_token: SecretStr = SecretStr("")

    aws_region: str = "us-east-1"
    bedrock_model_id: str = "claude-opus-5"
    bedrock_endpoint_url: str = ""

    ldap_url: str = ""
    ldap_base_dn: str = ""
    #: The DN template `app/auth/ldap.py` binds as, e.g.
    #: ``uid={username},{base_dn}`` (LDAP-standard) or
    #: ``{username}@example.com`` (AD UPN binds) — directories differ in how
    #: they key a user's DN and this project has no real AD to confirm
    #: against. Left empty (the default) falls back to the
    #: ``uid={username},{base_dn}`` template `app/auth/ldap.py` assumes,
    #: which is itself unverified against a real directory — see that
    #: module's docstring. Set this explicitly once the real directory's
    #: shape is known.
    ldap_bind_dn_template: str = ""
    ldap_group_reviewer: str = ""
    ldap_group_approver: str = ""
    ldap_group_auditor: str = ""
    ldap_group_risk_manager: str = ""
    ldap_group_requester: str = ""
    ldap_group_admin: str = ""

    #: Where the fake servers listen when adapter_mode is FAKE.
    fake_iq_url: str = "http://localhost:9101"
    fake_jfrog_url: str = "http://localhost:9102"
    fake_bitbucket_url: str = "http://localhost:9103"
    fake_bedrock_url: str = "http://localhost:9104"

    session_secret: SecretStr = SecretStr("dev-only-change-me")
    #: How long a session cookie is valid after login, in hours. A security
    #: parameter, not a constant: a value that requires a code change to
    #: adjust does not get adjusted.
    session_ttl_hours: int = 12
    #: Whether the session cookie carries the `Secure` flag (HTTPS only).
    #: **Must be true in any deployment reachable from outside the host** —
    #: false only for local HTTP development. Cloudflare terminates TLS at
    #: the edge in front of Traefik, so this app itself sees plain HTTP even
    #: in a real deployment; there is no way to derive "am I actually
    #: reachable over HTTPS" from inside the process, so this is a setting,
    #: not an inference.
    session_cookie_secure: bool = False

    @model_validator(mode="after")
    def _real_mode_needs_endpoints(self) -> Settings:
        if self.adapter_mode is not AdapterMode.REAL:
            return self
        missing = [
            name
            for name in ("iq_base_url", "jfrog_base_url", "bitbucket_base_url")
            if not getattr(self, name)
        ]
        if missing:
            raise ValueError(
                f"adapter_mode=real requires {', '.join(missing)} — a half-configured "
                "real deployment reaches production for some calls and fails for others"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
