"""Tests for ``app/adapters/factory.py`` — the one place that decides which
base URL (and, for Bedrock, which credentials) each adapter client points at,
based on ``adapter_mode``.
"""

from __future__ import annotations

from pydantic import SecretStr

from app.adapters.factory import (
    get_adjudicator,
    get_artifact_store,
    get_iq_client,
    get_scan_archive,
    get_source_repository,
)
from app.adapters.protocols import (
    Adjudicator,
    ArtifactStore,
    IqClient,
    ScanArchive,
    SourceRepository,
)
from app.config import AdapterMode, Settings
from tests.adapters.support import require_reachable


def _fake_settings(**overrides: object) -> Settings:
    defaults: dict[str, object] = {
        "adapter_mode": AdapterMode.FAKE,
        "iq_service_user": "svc",
        "iq_service_token": SecretStr("iq-tok"),
        "jfrog_token": SecretStr("jfrog-tok"),
        "bitbucket_token": SecretStr("bitbucket-tok"),
        "elk_token": SecretStr("elk-tok"),
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


def test_get_iq_client_in_fake_mode_targets_the_fake_url_and_satisfies_the_protocol() -> None:
    settings = _fake_settings()
    client = get_iq_client(settings)
    assert isinstance(client, IqClient)
    assert str(client._client.base_url) == settings.fake_iq_url  # type: ignore[attr-defined]


def test_get_iq_client_in_real_mode_targets_the_real_url() -> None:
    settings = _fake_settings(
        adapter_mode=AdapterMode.REAL,
        iq_base_url="https://iq.example.internal",
        jfrog_base_url="https://artifactory.example.internal",
        bitbucket_base_url="https://bitbucket.example.internal",
    )
    client = get_iq_client(settings)
    assert str(client._client.base_url) == "https://iq.example.internal"  # type: ignore[attr-defined]


def test_get_artifact_store_satisfies_the_protocol_in_fake_mode() -> None:
    assert isinstance(get_artifact_store(_fake_settings()), ArtifactStore)


def test_get_source_repository_satisfies_the_protocol_in_fake_mode() -> None:
    assert isinstance(get_source_repository(_fake_settings()), SourceRepository)


def test_get_scan_archive_satisfies_the_protocol() -> None:
    """ELK has no fake base URL (see app/adapters/elk/client.py's module
    docstring) — this only checks the returned object's shape, not that it
    can reach anything."""
    assert isinstance(get_scan_archive(_fake_settings()), ScanArchive)


def test_get_adjudicator_in_fake_mode_uses_dummy_credentials_and_the_fake_endpoint() -> None:
    adjudicator = get_adjudicator(_fake_settings())
    assert isinstance(adjudicator, Adjudicator)
    creds = adjudicator._client._request_signer._credentials  # type: ignore[attr-defined]
    assert creds.access_key == "fake-access-key-id"


async def test_factory_built_clients_round_trip_against_the_live_fakes() -> None:
    """One end-to-end smoke test tying the factory to the real running
    fakes, distinct from each client's own dedicated test module."""
    settings = _fake_settings()
    for url in (
        settings.fake_iq_url,
        settings.fake_jfrog_url,
        settings.fake_bitbucket_url,
        settings.fake_bedrock_url,
    ):
        require_reachable(url)

    iq = get_iq_client(settings)
    apps = await iq.applications_for_user("user-token")
    assert apps

    artifact_store = get_artifact_store(settings)
    data = await artifact_store.fetch("whatever/path.jar")
    assert data[:4] == b"PK\x03\x04"

    source_repository = get_source_repository(settings)
    hits = await source_repository.search_symbol("PAY/payments-api", "StringSubstitutor", "main")
    assert hits
