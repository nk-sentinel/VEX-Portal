"""The real AWS Bedrock adjudicator client — the one implementation, run
here against ``fakes/bedrock`` and at work against the real Bedrock Runtime.

**Bedrock uses boto3, not httpx — the one place "one client, two URLs" does
not hold as cleanly as it does for the other four adapters.** boto3's own
``endpoint_url=`` override exists exactly for pointing a service client
somewhere other than AWS (this is the same mechanism LocalStack-style test
doubles rely on), so this client uses boto3 in *both* modes and swaps only
``endpoint_url`` — the fake in ``fakes/bedrock`` exposes an
``InvokeModel``-shaped HTTP endpoint (``POST /model/{model_id}/invoke``,
Bedrock Runtime's real route) precisely so this is possible. The alternative
— httpx against the fake, boto3 only in real mode — was rejected: it would
mean the boto3 code path (request signing, the ``botocore`` exception
handling below, the real client construction) is *never exercised here at
all*, which is exactly the failure mode this whole task exists to avoid
("the real path stays untested until the work environment, which is the one
place we cannot debug it"). ``app/adapters/factory.py`` is the one place
that decides the ``endpoint_url``/credentials difference between modes.

**Credentials in fake mode.** boto3 requires *some* credentials to construct
a client and sign a SigV4 request, even against a fake that never checks
them (``fakes/bedrock/main.py``: "SigV4 request signing is not verified —
this fake is a local test double, not an auth boundary"). Rather than fall
back to boto3's ambient credential-provider chain (environment, shared
config file, EC2/ECS instance metadata — unpredictable on a dev host, and
the instance-metadata step in particular can add real latency while it times
out), the factory passes explicit, obviously-fake static credentials in fake
mode. In real mode no credentials are passed at all, so boto3's normal
chain — an IAM role, in the work network — applies unchanged.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, ConnectTimeoutError, ReadTimeoutError

from app.adapters._transport import MAX_ATTEMPTS
from app.adapters.errors import (
    AdapterError,
    UpstreamResponseError,
    UpstreamTimeout,
    UpstreamUnavailable,
)
from app.adapters.protocols import AiVerdictDto, FindingRef
from app.domain.determination import Confidence, Justification, State
from app.evidence.pack import EvidencePack

_TOOL_NAME = "emit_verdict"
_ANTHROPIC_VERSION = "bedrock-2023-05-31"
_MAX_TOKENS = 1024


class MalformedAdjudication(AdapterError):
    """Bedrock answered 200, but the response body carried no ``tool_use``
    block — the forced-tool-call contract this client relies on for
    closed-enum output was not honoured."""


def _build_prompt(pack: EvidencePack, finding: FindingRef) -> str:
    """Render the fixed evidence pack as the adjudicator's entire input.

    Never a free-form question (``docs/design.md``, "AI adjudication") — the
    model is handed exactly what was collected and asked to classify it
    through a forced tool call, never given room to go looking for more.
    """
    component = next((c for c in pack.components if c.cve == finding.cve), None)
    evidence = {
        "application_id": finding.application_id,
        "cve": finding.cve,
        "purl": finding.purl,
        "provenance_verdict": pack.provenance.verdict.value,
        "class_present": component.class_present if component else None,
        "referenced": component.referenced if component else None,
        "reference_scan_conclusive": component.reference_scan_conclusive if component else None,
        "escape_hatches": [
            {"kind": hatch.kind, "location": hatch.location} for hatch in pack.escape_hatches
        ],
    }
    return (
        f"Adjudicate finding {finding.cve} against {finding.purl} in application "
        f"{finding.application_id} using only this evidence:\n{json.dumps(evidence)}"
    )


class BedrockAdjudicator:
    """The AI adjudicator, over AWS Bedrock's InvokeModel API.

    The same class runs against ``fakes/bedrock`` (``adapter_mode=fake``) and
    the real Bedrock Runtime (``adapter_mode=real``) — see this module's
    docstring and ``app/adapters/factory.py``.
    """

    def __init__(
        self,
        *,
        model_id: str,
        region: str,
        endpoint_url: str | None,
        access_key: str | None = None,
        secret_key: str | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._model_id = model_id
        config = Config(
            connect_timeout=5.0,
            read_timeout=timeout_seconds,
            retries={"max_attempts": MAX_ATTEMPTS, "mode": "standard"},
        )
        client_kwargs: dict[str, Any] = {
            "region_name": region,
            "endpoint_url": endpoint_url,
            "config": config,
        }
        if access_key is not None:
            client_kwargs["aws_access_key_id"] = access_key
            client_kwargs["aws_secret_access_key"] = secret_key
        self._client = boto3.client("bedrock-runtime", **client_kwargs)

    async def adjudicate(self, pack: EvidencePack, finding: FindingRef) -> AiVerdictDto:
        """Ask the adjudicator for a verdict on ``finding``, given the fixed
        evidence in ``pack``.

        Runs boto3's synchronous ``invoke_model`` in a thread so this
        coroutine never blocks the event loop — boto3 has no async API.
        """
        body = {
            "anthropic_version": _ANTHROPIC_VERSION,
            "max_tokens": _MAX_TOKENS,
            "tool_choice": {"type": "tool", "name": _TOOL_NAME},
            "tools": [
                {
                    "name": _TOOL_NAME,
                    "description": "Emit the closed-enum adjudication verdict for this finding.",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "state": {"type": "string"},
                            "justification": {"type": ["string", "null"]},
                            "confidence": {"type": "string"},
                            "evidence_refs": {"type": "array", "items": {"type": "string"}},
                            "missing_evidence": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["state", "confidence", "evidence_refs", "missing_evidence"],
                    },
                }
            ],
            "messages": [{"role": "user", "content": _build_prompt(pack, finding)}],
        }
        payload = await asyncio.to_thread(self._invoke, body)
        return _parse_verdict(payload)

    def _invoke(self, body: dict[str, Any]) -> dict[str, Any]:
        path = f"/model/{self._model_id}/invoke"
        try:
            response = self._client.invoke_model(
                modelId=self._model_id,
                body=json.dumps(body).encode("utf-8"),
                contentType="application/json",
                accept="application/json",
            )
        except (ConnectTimeoutError, ReadTimeoutError) as exc:
            raise UpstreamTimeout(f"POST {path} timed out") from exc
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 502)
            raise UpstreamResponseError("POST", path, status) from exc
        except BotoCoreError as exc:
            raise UpstreamUnavailable(f"POST {path} could not be reached") from exc
        result: dict[str, Any] = json.loads(response["body"].read())
        return result


def _parse_verdict(payload: dict[str, Any]) -> AiVerdictDto:
    tool_use = next(
        (block for block in payload.get("content", []) if block.get("type") == "tool_use"), None
    )
    if tool_use is None:
        raise MalformedAdjudication("bedrock response contained no tool_use block")
    verdict_input = tool_use["input"]
    justification = verdict_input.get("justification")
    return AiVerdictDto(
        state=State(verdict_input["state"]),
        justification=Justification(justification) if justification else None,
        confidence=Confidence(verdict_input["confidence"]),
        evidence_refs=list(verdict_input.get("evidence_refs", [])),
        missing_evidence=list(verdict_input.get("missing_evidence", [])),
    )
