"""Chooses which base URL (and, for Bedrock, which credentials) each real
adapter client points at, based on ``adapter_mode`` — the only difference
between running here, against the fakes, and at work, against the real
systems.

Every function here returns the *same* concrete class regardless of mode —
see each ``app/adapters/{iq,jfrog,bitbucket,llm,elk}/client.py`` module's own
docstring for why that single-implementation design is the point of this
whole task. This module is the one place that decision about *which base URL*
gets made; nothing else in the portal should be constructing an adapter
client directly.
"""

from __future__ import annotations

from app.adapters.bitbucket.client import BitbucketHttpClient
from app.adapters.elk.client import ElkHttpClient
from app.adapters.iq.client import IqHttpClient
from app.adapters.jfrog.client import JFrogHttpClient
from app.adapters.llm.client import BedrockAdjudicator
from app.adapters.protocols import (
    Adjudicator,
    ArtifactStore,
    IqClient,
    ScanArchive,
    SourceRepository,
)
from app.config import AdapterMode, Settings, get_settings

#: Obviously-fake AWS credentials, used only when adapter_mode is FAKE — see
#: app/adapters/llm/client.py's module docstring for why boto3 needs *some*
#: credentials even against a fake that never checks them.
_FAKE_AWS_ACCESS_KEY_ID = "fake-access-key-id"
_FAKE_AWS_SECRET_ACCESS_KEY = "fake-secret-access-key"  # noqa: S105 - not a real credential


def get_iq_client(settings: Settings | None = None) -> IqClient:
    s = settings or get_settings()
    base_url = s.iq_base_url if s.adapter_mode is AdapterMode.REAL else s.fake_iq_url
    return IqHttpClient(
        base_url=base_url,
        service_user=s.iq_service_user,
        service_token=s.iq_service_token.get_secret_value(),
    )


def get_artifact_store(settings: Settings | None = None) -> ArtifactStore:
    s = settings or get_settings()
    base_url = s.jfrog_base_url if s.adapter_mode is AdapterMode.REAL else s.fake_jfrog_url
    return JFrogHttpClient(base_url=base_url, token=s.jfrog_token.get_secret_value())


def get_source_repository(settings: Settings | None = None) -> SourceRepository:
    s = settings or get_settings()
    base_url = s.bitbucket_base_url if s.adapter_mode is AdapterMode.REAL else s.fake_bitbucket_url
    return BitbucketHttpClient(base_url=base_url, token=s.bitbucket_token.get_secret_value())


def get_scan_archive(settings: Settings | None = None) -> ScanArchive:
    """Build the ELK client.

    Unlike the other three httpx-backed adapters, this always uses
    ``settings.elk_base_url`` regardless of ``adapter_mode`` — there is no
    ``fake_elk_url`` in ``app/config.py`` and no fake ELK server to point at
    (see ``app/adapters/elk/client.py``'s module docstring). In a FAKE
    deployment with ``elk_base_url`` unset (the default), a call through the
    client this returns will fail with a connection error the first time it
    is used; every other behaviour is covered by
    ``tests/adapters/test_elk_client.py`` against ``httpx.MockTransport``
    instead of a live round trip. Flagged in the Task 8 report.
    """
    s = settings or get_settings()
    return ElkHttpClient(
        base_url=s.elk_base_url, token=s.elk_token.get_secret_value(), index=s.elk_index
    )


def get_adjudicator(settings: Settings | None = None) -> Adjudicator:
    s = settings or get_settings()
    if s.adapter_mode is AdapterMode.REAL:
        return BedrockAdjudicator(
            model_id=s.bedrock_model_id,
            region=s.aws_region,
            endpoint_url=s.bedrock_endpoint_url or None,
        )
    return BedrockAdjudicator(
        model_id=s.bedrock_model_id,
        region=s.aws_region,
        endpoint_url=s.fake_bedrock_url,
        access_key=_FAKE_AWS_ACCESS_KEY_ID,
        secret_key=_FAKE_AWS_SECRET_ACCESS_KEY,
    )
