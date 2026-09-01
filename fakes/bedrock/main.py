"""Fake AWS Bedrock (InvokeModel) server.

THROWAWAY — see /fakes/README.md at the repo root before touching this
file.

This is the subtlest of the four fakes (see the Task 7 brief): it has to
return a valid adjudication in the *exact* response envelope Bedrock's
InvokeModel API uses for an Anthropic Claude model, not a convenient
shortcut, so app.adapters.llm.client's parsing and the strict-output
contract (docs/design.md, "AI adjudication") are actually exercised here
rather than discovered for the first time at work.

Route: ``POST /model/{model_id}/invoke`` — this is the real Bedrock Runtime
path boto3's ``invoke_model()`` calls (``bedrock_endpoint_url`` /
``fake_bedrock_url`` in app/config.py is exactly the ``endpoint_url=``
override boto3 accepts for pointing a service client somewhere other than
AWS). SigV4 request signing is not verified — this fake is a local test
double, not an auth boundary.

The response body is the native Anthropic Messages API shape (``id``,
``type``, ``role``, ``model``, ``content``, ``stop_reason``,
``stop_sequence``, ``usage``) — that is what Bedrock hands back verbatim
inside the InvokeModel response body for Claude models. The verdict itself
is returned as a forced ``tool_use`` block, which is how a real client gets
closed-enum, schema-shaped output out of Claude rather than parsing free
text — see docs/design.md's "closed enum only" output contract.

Since there is no real model behind this fake, verdicts are canned per CVE
(fakes/data/bedrock.json) and selected by looking for a known CVE id
literally inside the request body. Anything unrecognised — including a
request that doesn't mention any of the sample CVEs — gets the abstain
verdict (``confidence: insufficient_evidence``) rather than a fabricated
confident one. This is deliberate, not just a fallback: the brief requires
at least one canned response that abstains, because that is the path that
routes a finding to human review, and a fake that only ever returns
confident verdicts would leave that path unexercised.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import FastAPI

from fakes._shared import load_json

app = FastAPI(title="fake-bedrock-runtime")

_DATA = load_json("bedrock.json")


def _select_verdict(body: dict[str, Any]) -> dict[str, Any]:
    haystack = json.dumps(body)
    for cve, verdict in _DATA["verdicts_by_cve"].items():
        if cve in haystack:
            return dict(verdict)
    return dict(_DATA["default_verdict"])


@app.post("/model/{model_id}/invoke")
async def invoke_model(model_id: str, body: dict[str, Any]) -> dict[str, Any]:
    verdict = _select_verdict(body)
    prompt_chars = len(json.dumps(body))
    return {
        "id": f"msg_{uuid.uuid4().hex[:24]}",
        "type": "message",
        "role": "assistant",
        "model": model_id,
        "content": [
            {
                "type": "tool_use",
                "id": f"toolu_{uuid.uuid4().hex[:24]}",
                "name": _DATA["tool_name"],
                "input": verdict,
            }
        ],
        "stop_reason": "tool_use",
        "stop_sequence": None,
        "usage": {
            # Not a real tokenizer count — proportional to request size so
            # the field is at least a plausible-looking positive integer
            # rather than a hardcoded constant on every call.
            "input_tokens": max(1, prompt_chars // 4),
            "output_tokens": 64,
        },
    }
