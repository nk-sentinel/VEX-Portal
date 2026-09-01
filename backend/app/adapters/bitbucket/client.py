"""The real Bitbucket Data Center client — the one implementation, run here
against ``fakes/bitbucket`` and at work against the real Bitbucket DC.

Bitbucket *Data Center* (self-hosted), not Bitbucket Cloud — a different
product with a different REST API (see ``fakes/bitbucket/main.py`` and
``docs/design.md``'s "Environment" section).

**The ``repo`` convention.** ``SourceRepository``'s Protocol methods
(``app/adapters/protocols.py``) take a single ``repo: str``, but Bitbucket DC
addresses a repository with two parts: a project key and a repo slug
(``/projects/{key}/repos/{slug}``). Nothing else in this codebase specifies
how those two collapse into one string, so this client defines the
convention itself: ``repo`` is ``"{projectKey}/{repoSlug}"`` (the same shape
GitHub-style "owner/repo" identifiers use), split on the first ``/``.

**Search is not scoped to ``repo``/``ref`` by IQ's own query.** Bitbucket
Server's code search supports a query DSL (``project:X repo:Y term``), but
the fake's search is a plain substring match over the raw query string and
does not implement it (this is Task 7's own least-confirmed vendor shape —
see ``fakes/README.md``). Rather than build DSL syntax into the request that
the fake cannot honour (making the round trip here misleading about what was
actually verified), this client sends the bare ``symbol`` and filters the
results to the requested project/repo client-side, using the
project/repository fields every hit already carries. This is a documented
simplification, not a confirmed real shape — verify Bitbucket DC's actual
query DSL against the real server before relying on it to scope a large
result set server-side. ``ref`` is accepted (the Protocol requires it) but is
not filterable: Bitbucket Server's code search does not scope results to an
arbitrary ref.
"""

from __future__ import annotations

import httpx

from app.adapters._transport import DEFAULT_TIMEOUT, get_or_none, raise_for_status, send
from app.adapters.protocols import SymbolHit


def _split_repo(repo: str) -> tuple[str, str]:
    project_key, separator, repo_slug = repo.partition("/")
    if not separator:
        raise ValueError(f"repo must be '{{projectKey}}/{{repoSlug}}', got {repo!r}")
    return project_key, repo_slug


def _strip_highlight_markup(text: str) -> str:
    """Bitbucket Server wraps a search hit's matched region in ``<em>`` —
    real, HTML-formatted output, not plain text (see
    ``fakes/bitbucket/main.py``'s ``_highlight``). A client that read this
    as plain text would carry literal ``<em>``/``</em>`` into every snippet.
    """
    return text.replace("<em>", "").replace("</em>", "")


class BitbucketHttpClient:
    """Everything the portal needs from Bitbucket Data Center, over real
    HTTP.

    The same class runs against ``fakes/bitbucket`` (``adapter_mode=fake``)
    and the real Bitbucket DC instance (``adapter_mode=real``) — see
    ``app/adapters/factory.py``.
    """

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=DEFAULT_TIMEOUT,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def search_symbol(self, repo: str, symbol: str, ref: str) -> list[SymbolHit]:
        """Search source in ``repo`` for ``symbol`` — the Tier 2 companion
        check to constant-pool analysis (``docs/design.md``, Tier 2 rule #7).

        Never 404s (a search with no hits is a 200 with an empty result, not
        an absence at the HTTP layer) — any non-2xx here is an error.
        """
        path = "/rest/search/latest/search"
        response = await send(
            self._client, "POST", path, json={"query": symbol, "entities": {"code": {}}}
        )
        raise_for_status("POST", path, response)

        project_key, repo_slug = _split_repo(repo)
        hits: list[SymbolHit] = []
        for value in response.json().get("code", {}).get("values", []):
            file_info = value["file"]
            if (
                file_info["project"]["key"] != project_key
                or file_info["repository"]["slug"] != repo_slug
            ):
                continue
            file_path = file_info["path"]["toString"]
            for context in value.get("hitContexts", []):
                for hit in context:
                    hits.append(
                        SymbolHit(
                            path=file_path,
                            line=hit["line"],
                            snippet=_strip_highlight_markup(hit["text"]),
                        )
                    )
        return hits

    async def file(self, repo: str, path: str, ref: str) -> bytes | None:
        """Fetch one file's raw content at ``ref``.

        404s as an absence — whether the repository itself is unknown or
        just this path within it, both collapse to "this file is not there",
        which is exactly what the ``bytes | None`` return type expresses.
        """
        project_key, repo_slug = _split_repo(repo)
        url_path = f"/rest/api/1.0/projects/{project_key}/repos/{repo_slug}/raw/{path}"
        response = await get_or_none(self._client, url_path, params={"at": ref})
        if response is None:
            return None
        return response.content
