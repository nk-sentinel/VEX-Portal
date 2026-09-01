"""Fake Bitbucket Data Center server.

THROWAWAY — see /fakes/README.md at the repo root before touching this
file. Bitbucket *Data Center* (self-hosted), not Bitbucket Cloud — a
different product with a different REST API; see docs/design.md's
"Environment" section.

Serves a raw file fetch (``GET .../raw/{path}``, confirmed against
Atlassian's own REST API docs) and a code-search endpoint
(``POST /rest/search/latest/search``) over one small canned repository
tree, matching the same payments-api sample the fake IQ report and fake
JFrog artifact describe — a symbol search for ``StringSubstitutor`` here
finds the same reference the artifact's constant-pool scan does.

The code-search response shape is the least-confirmed of the four fakes'
vendor shapes — see fakes/README.md and the Task 7 report.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Response

from fakes._shared import load_json

app = FastAPI(title="fake-bitbucket-datacenter")

_DATA = load_json("bitbucket.json")
_FILES: dict[str, str] = _DATA["files"]


def _path_dto(path: str) -> dict[str, Any]:
    components = path.split("/")
    name = components[-1]
    extension = name.rsplit(".", 1)[1] if "." in name else ""
    return {
        "components": components,
        "parent": "/".join(components[:-1]),
        "name": name,
        "extension": extension,
        "toString": path,
    }


@app.get("/rest/api/1.0/projects/{project_key}/repos/{repo_slug}/raw/{file_path:path}")
async def raw_file(
    project_key: str, repo_slug: str, file_path: str, at: str | None = None
) -> Response:
    if project_key != _DATA["project_key"] or repo_slug != _DATA["repo_slug"]:
        raise HTTPException(status_code=404, detail="repository not found")
    content = _FILES.get(file_path)
    if content is None:
        raise HTTPException(status_code=404, detail="file not found")
    return Response(content=content.encode("utf-8"), media_type="text/plain")


@app.post("/rest/search/latest/search")
async def search(body: dict[str, Any]) -> dict[str, Any]:
    query = body.get("query", "")
    values = []
    if query:
        for path, content in _FILES.items():
            hits = [
                {"line": lineno, "text": _highlight(line, query)}
                for lineno, line in enumerate(content.splitlines(), start=1)
                if query.lower() in line.lower()
            ]
            if hits:
                values.append(
                    {
                        "file": {
                            "path": _path_dto(path),
                            "revision": {"id": _DATA["default_ref"]},
                            "project": {"key": _DATA["project_key"]},
                            "repository": {"slug": _DATA["repo_slug"]},
                        },
                        # Real Bitbucket Server nests one hit-context list per
                        # matched region; a single contiguous match per file is
                        # the only case this canned tree needs to represent.
                        "hitContexts": [hits],
                    }
                )
    return {
        "query": query,
        "code": {"count": len(values), "values": values},
    }


def _highlight(line: str, query: str) -> str:
    """Wrap the match in <em>, matching Bitbucket's own HTML-formatted
    hitContexts — a real client must strip this, not just read it as plain
    text. See fakes/README.md.
    """
    lower_line = line.lower()
    lower_query = query.lower()
    start = lower_line.find(lower_query)
    if start == -1:
        return line
    end = start + len(query)
    return f"{line[:start]}<em>{line[start:end]}</em>{line[end:]}"
