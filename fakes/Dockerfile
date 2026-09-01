# Fake Nexus IQ / JFrog / Bitbucket / Bedrock servers — THROWAWAY scaffolding.
#
# These stand in for the four systems this portal talks to but that
# shadowlab cannot reach (see /fakes/README.md). One image, shared by all
# four `vex-fake-*` services in compose.yaml — which fake a container runs
# is chosen entirely by that service's `command:`, not by anything baked
# into this image.
#
# Never used at work. Never imported by backend/app/. Pinned to the exact
# fastapi/uvicorn versions backend/pyproject.toml already uses — no new
# dependency was introduced to build this.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN pip install "fastapi==0.136.3" "uvicorn[standard]==0.48.0"

# Built from the repo root (see compose.yaml's `build.context`) so this can
# copy the whole fakes/ tree, including fakes/data/, in one shot.
COPY fakes ./fakes
