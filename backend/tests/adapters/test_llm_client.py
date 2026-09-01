"""Tests for the real Bedrock adjudicator client
(``app/adapters/llm/client.py``).

Happy-path and malformed-response cases round-trip over real HTTP against
``fakes/bedrock`` (boto3's ``endpoint_url=`` pointed at it — see this
module's own docstring for why this exercises the *same* boto3 code path
"real mode" uses, not a separate httpx-only fake path). A genuine timeout and
5xx are hard to make a well-behaved fake produce on purpose, so those two use
``unittest.mock`` on the boto3 client's own ``invoke_model`` method — still
the real ``BedrockAdjudicator._invoke`` exception-translation code under
test, just fed a synthetic ``botocore`` exception instead of one from a
contrived server. The connection-failure and secret-leak cases point at a
genuinely unused local port, so those two ARE real network failures.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from app.adapters.errors import UpstreamResponseError, UpstreamTimeout, UpstreamUnavailable
from app.adapters.llm.client import BedrockAdjudicator, MalformedAdjudication
from app.adapters.protocols import Adjudicator, FindingRef
from app.evidence.pack import EvidencePack
from app.provenance.fingerprint import FingerprintResult, Verdict
from tests.adapters.support import BEDROCK_BASE_URL, require_reachable

MODEL_ID = "anthropic.claude-opus-5-20260101-v1:0"
_SECRET = "aws-secret-access-key-8f7e6d5c4b3a"

_PACK = EvidencePack(
    provenance=FingerprintResult(
        verdict=Verdict.MATCH,
        matched=7,
        report_total=7,
        unmatched_report_hashes=[],
        unmatched_artifact_hashes=[],
        surplus_ratio=0.0,
        ratio=1.0,
    )
)


@pytest.fixture
def client() -> BedrockAdjudicator:
    require_reachable(BEDROCK_BASE_URL)
    return BedrockAdjudicator(
        model_id=MODEL_ID,
        region="us-east-1",
        endpoint_url=BEDROCK_BASE_URL,
        access_key="fake-access-key-id",
        secret_key=_SECRET,
    )


def test_bedrock_adjudicator_satisfies_the_protocol(client: BedrockAdjudicator) -> None:
    assert isinstance(client, Adjudicator)


async def test_adjudicate_round_trips_the_clear_cut_affected_case(
    client: BedrockAdjudicator,
) -> None:
    finding = FindingRef(application_id="app-1", cve="CVE-2022-42889", purl="pkg:maven/x/y@1.0")
    verdict = await client.adjudicate(_PACK, finding)
    assert verdict.state.value == "affected"
    assert verdict.confidence.value == "high"
    assert verdict.evidence_refs


async def test_adjudicate_abstains_for_the_ambiguous_case(client: BedrockAdjudicator) -> None:
    finding = FindingRef(application_id="app-1", cve="CVE-2021-44228", purl="pkg:maven/x/y@1.0")
    verdict = await client.adjudicate(_PACK, finding)
    assert verdict.confidence.abstains()


async def test_adjudicate_defaults_to_abstain_for_an_unrecognised_finding(
    client: BedrockAdjudicator,
) -> None:
    finding = FindingRef(
        application_id="app-1", cve="CVE-9999-does-not-exist", purl="pkg:maven/x/y@1.0"
    )
    verdict = await client.adjudicate(_PACK, finding)
    assert verdict.confidence.abstains()
    assert verdict.missing_evidence


def _streaming(payload: dict) -> MagicMock:
    body = MagicMock()
    body.read.return_value = json.dumps(payload).encode("utf-8")
    return body


async def test_malformed_response_with_no_tool_use_block_raises(
    client: BedrockAdjudicator,
) -> None:
    text_only_payload = {"content": [{"type": "text", "text": "not a tool call"}]}
    client._client.invoke_model = MagicMock(  # type: ignore[method-assign]
        return_value={"body": _streaming(text_only_payload)}
    )
    finding = FindingRef(application_id="app-1", cve="CVE-2022-42889", purl="pkg:maven/x/y@1.0")
    with pytest.raises(MalformedAdjudication):
        await client.adjudicate(_PACK, finding)


async def test_5xx_raises_a_typed_error(client: BedrockAdjudicator) -> None:
    client._client.invoke_model = MagicMock(  # type: ignore[method-assign]
        side_effect=ClientError(
            {
                "Error": {"Code": "InternalServerException", "Message": "boom"},
                "ResponseMetadata": {"HTTPStatusCode": 500},
            },
            "InvokeModel",
        )
    )
    finding = FindingRef(application_id="app-1", cve="CVE-2022-42889", purl="pkg:maven/x/y@1.0")
    with pytest.raises(UpstreamResponseError) as exc_info:
        await client.adjudicate(_PACK, finding)
    assert exc_info.value.status_code == 500


async def test_timeout_raises_a_typed_error(client: BedrockAdjudicator) -> None:
    client._client.invoke_model = MagicMock(  # type: ignore[method-assign]
        side_effect=ReadTimeoutError(endpoint_url=BEDROCK_BASE_URL)
    )
    finding = FindingRef(application_id="app-1", cve="CVE-2022-42889", purl="pkg:maven/x/y@1.0")
    with pytest.raises(UpstreamTimeout):
        await client.adjudicate(_PACK, finding)


async def test_connection_failure_raises_a_typed_error() -> None:
    # A genuinely unused local port — a real connection failure, not mocked.
    client = BedrockAdjudicator(
        model_id=MODEL_ID,
        region="us-east-1",
        endpoint_url="http://localhost:9199",
        access_key="fake-access-key-id",
        secret_key=_SECRET,
        timeout_seconds=2.0,
    )
    finding = FindingRef(application_id="app-1", cve="CVE-2022-42889", purl="pkg:maven/x/y@1.0")
    with pytest.raises((UpstreamUnavailable, UpstreamTimeout)):
        await client.adjudicate(_PACK, finding)


async def test_no_secret_appears_in_exception_or_logs_on_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Real connection failure against boto3's own request path — the actual
    # secret key is what boto3 uses to sign the (never-sent) request, so
    # this exercises the real signing path, not a stand-in for it.
    client = BedrockAdjudicator(
        model_id=MODEL_ID,
        region="us-east-1",
        endpoint_url="http://localhost:9199",
        access_key="fake-access-key-id",
        secret_key=_SECRET,
        timeout_seconds=2.0,
    )
    finding = FindingRef(application_id="app-1", cve="CVE-2022-42889", purl="pkg:maven/x/y@1.0")

    expected = (UpstreamUnavailable, UpstreamTimeout)
    with caplog.at_level("DEBUG"), pytest.raises(expected) as exc_info:
        await client.adjudicate(_PACK, finding)

    assert _SECRET not in str(exc_info.value)
    assert _SECRET not in repr(exc_info.value)
    assert _SECRET not in caplog.text
