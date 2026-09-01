"""The real ELK (Elasticsearch) client — the one implementation. Unlike the
other four adapters, there is **no fake server to run it against here.**

``fakes/`` (see ``fakes/README.md``) stands in for "the systems shadowlab
cannot reach": Nexus IQ, JFrog Artifactory, Bitbucket Data Center, and AWS
Bedrock. ELK was never in that list — going back to the plan's first task
(``app/config.py`` has ``elk_base_url``/``elk_index``/``elk_token`` but no
``fake_elk_url``, unlike the other four systems, which each got one), and the
Task 7 brief's fakes list names only IQ/JFrog/Bitbucket/Bedrock. Nothing
under ``backend/`` currently starts a live process this client can round-trip
against, so — unlike the other four adapters, which are exercised over real
HTTP against a running fake process — this client is exercised with
``httpx.MockTransport`` (real ``httpx.AsyncClient`` request/response
machinery, no live process): every failure-taxonomy behaviour this module
implements is genuinely exercised, but "answers over real HTTP the way the
other four are checked" is not. Flagged in the Task 8 report for the plan
owner: either accept ``httpx.MockTransport`` coverage as sufficient given
``ScanRecord``'s shape is already documented as the weakest, provisional one
of the five (Task 6, Ruling 11), or add a fifth fake server in a follow-up
task.

**Response shape.** No confirmed real ELK document shape exists anywhere in
this repository (``docs/design.md`` calls ``ScanRecord`` provisional). This
client assumes the ordinary Elasticsearch ``_search`` API against
``elk_index`` — a query-string endpoint that always answers ``200``, even
for zero hits (Elasticsearch has no 404 concept for a search; "no results"
and "some results" are both success responses that differ only in
``hits.hits``), filtering ``scan_id`` as a term and reading one document's
``_source`` as ``components``/``cve_ids``. This is a reasonable, standard
Elasticsearch query shape, not a confirmed one — verify against the real
index mapping before relying on it at work.
"""

from __future__ import annotations

import httpx

from app.adapters._transport import DEFAULT_TIMEOUT, raise_for_status, send
from app.adapters.protocols import ReportComponent, ScanRecord


class ElkHttpClient:
    """Everything the portal needs from ELK, over real HTTP.

    The same class is meant to run against a fake here and the real ELK
    cluster at work — see this module's docstring for why only the latter is
    currently possible; ``app/adapters/factory.py`` always uses
    ``settings.elk_base_url`` regardless of ``adapter_mode`` until that gap
    is resolved.
    """

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        index: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._index = index
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=DEFAULT_TIMEOUT,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def sbom_for_scan(self, scan_id: str) -> ScanRecord | None:
        """Reference — never copy — one scan's decision-relevant SBOM and CVE
        extract (``docs/design.md``, "External systems": "Reference it,
        don't copy it").

        Absence here is "zero hits", not a 404 — Elasticsearch's ``_search``
        always answers 200.
        """
        path = f"/{self._index}/_search"
        response = await send(
            self._client,
            "POST",
            path,
            json={"query": {"term": {"scan_id.keyword": scan_id}}, "size": 1},
        )
        raise_for_status("POST", path, response)

        hits = response.json().get("hits", {}).get("hits", [])
        if not hits:
            return None
        source = hits[0]["_source"]
        components = [
            ReportComponent(purl=c["purl"], sha1=c["sha1"]) for c in source.get("components", [])
        ]
        return ScanRecord(
            scan_id=source.get("scan_id", scan_id),
            components=components,
            cve_ids=list(source.get("cve_ids", [])),
        )
