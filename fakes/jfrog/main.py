"""Fake JFrog Artifactory server.

THROWAWAY — see /fakes/README.md at the repo root before touching this file.

Serves two things a real Artifactory does: a generic artifact download (any
path returns the one canned artifact — see below) and the Build Info API
(``GET /api/build/{name}/{number}``), shaped per docs/design.md's own
confirmed field names (``vcs: [{url, revision, branch}]``).

The artifact returned is a real, parseable Spring Boot fat JAR built with
the existing test factories (backend/tests/artifact/factories.py) — not a
stub — so app.evidence.pack.build_pack actually opens it. See
fakes/_shared.py for why it is a checked-in binary fixture rather than
built fresh on every request.

``ArtifactStore.fetch(coordinates)`` (app/adapters/protocols.py) treats
``coordinates`` as opaque to the portal — a repo-key/path string for a
JAR, an image reference for a container. Real Artifactory repo-key layout
is org-specific, so this fake does not try to validate or route on the
path; it returns the same canned artifact for whatever coordinates it is
asked for, which is the one thing this fake actually needs to promise.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Response

from fakes._shared import load_json, sample_artifact_bytes

app = FastAPI(title="fake-jfrog-artifactory")

_DATA = load_json("jfrog.json")
_ARTIFACT = sample_artifact_bytes()


@app.get("/api/build/{build_name}/{build_number}")
async def build_info(build_name: str, build_number: str) -> dict[str, Any]:
    info = _DATA["build_info"]
    if build_name != info["buildInfo"]["name"] or build_number != info["buildInfo"]["number"]:
        raise HTTPException(status_code=404, detail="build not found")
    return dict(info)


# Registered last: a generic download matches any path not already claimed
# by a more specific route above, mirroring how Artifactory serves a repo
# path directly rather than through a dedicated "/download" prefix.
@app.get("/{artifact_path:path}")
async def fetch_artifact(artifact_path: str) -> Response:
    if not artifact_path:
        raise HTTPException(status_code=404, detail="not found")
    return Response(content=_ARTIFACT, media_type="application/java-archive")
