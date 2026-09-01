"""The real JFrog Artifactory client — the one implementation, run here
against ``fakes/jfrog`` and at work against the real Artifactory instance.

``ArtifactStore`` treats ``coordinates`` as opaque (see
``app/adapters/protocols.py``): a repo-key/path string for a JAR/WAR, an
image reference for a container image. This client never inspects or routes
on it beyond using it as a path — that decision belongs to the caller and to
whichever repository layout the work environment actually uses.

**Build info resolution.** ``build_info(coordinates)`` is asked to answer
with the *same* opaque ``coordinates`` as ``fetch`` — but the real Build Info
API is keyed by ``(build name, build number)``, not by an artifact's own
path. The real, documented way to bridge the two is Artifactory's Item
Properties API (``GET /api/storage/{path}?properties=build.name,build.number``),
which returns the ``build.name``/``build.number`` properties Artifactory
attaches to an artifact when it is deployed with build info — then the
existing Build Info endpoint is queried with those. This client implements
that two-call chain; a minimal, vendor-shaped properties route was added to
``fakes/jfrog/main.py`` to exercise it (not in the Task 7 brief's list — see
``fakes/README.md``'s standing policy on adding the smallest fake route a
real client genuinely needs; flagged in the Task 8 report).
"""

from __future__ import annotations

import httpx

from app.adapters._transport import DEFAULT_TIMEOUT, get_or_none, get_required
from app.adapters.protocols import BuildInfo


class JFrogHttpClient:
    """Everything the portal needs from JFrog Artifactory, over real HTTP.

    The same class runs against ``fakes/jfrog`` (``adapter_mode=fake``) and
    the real Artifactory instance (``adapter_mode=real``) — see
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

    async def fetch(self, coordinates: str) -> bytes:
        """Download the artifact at ``coordinates``.

        404s as an error: the caller named these specific coordinates, and
        an artifact that is not there is something the caller needs to know
        about, not a legitimate absence to shrug off.
        """
        path = f"/{coordinates.lstrip('/')}"
        response = await get_required(self._client, path)
        return response.content

    async def build_info(self, coordinates: str) -> BuildInfo | None:
        """Look up the build (and therefore VCS) info published for the
        artifact at ``coordinates``, if the build that produced it published
        one.

        404/absent-properties is a typed absence, not an error — see
        ``docs/design.md``'s open item "confirm whether CI publishes JFrog
        Build Info": plenty of legitimate artifacts were never deployed with
        build info attached at all.
        """
        props_path = f"/api/storage/{coordinates.lstrip('/')}"
        props_response = await get_or_none(
            self._client, props_path, params={"properties": "build.name,build.number"}
        )
        if props_response is None:
            return None
        properties = props_response.json().get("properties", {})
        names = properties.get("build.name") or []
        numbers = properties.get("build.number") or []
        if not names or not numbers:
            return None

        build_path = f"/api/build/{names[0]}/{numbers[0]}"
        build_response = await get_or_none(self._client, build_path)
        if build_response is None:
            return None
        vcs_entries = build_response.json().get("buildInfo", {}).get("vcs", [])
        vcs = vcs_entries[0] if vcs_entries else {}
        return BuildInfo(
            repository_url=vcs.get("url"),
            commit_sha=vcs.get("revision"),
            branch=vcs.get("branch"),
        )
