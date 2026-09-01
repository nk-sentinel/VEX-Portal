# VEX Portal API — runtime image (FastAPI + SQLAlchemy async + Alembic).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install the pinned runtime dependencies from pyproject.toml (prod deps
# only — ruff, mypy and pytest have no place in a shipped image). Source is
# copied before install so setuptools' packages.find picks up `app`.
COPY pyproject.toml ./
COPY app ./app
RUN pip install .

# Alembic migrations are not run at container startup (see compose.yaml) —
# copied in so `docker compose exec vex-portal-api alembic upgrade head` (or
# a future entrypoint) can reach them, but nothing here applies them
# automatically.
COPY alembic ./alembic
COPY alembic.ini ./

EXPOSE 8000

# Liveness: the app's GET /health route. Read the response body rather than
# only the status code — the route ships specifically so an unhealthy
# process (adapter misconfigured, startup failed) is visible, not just
# "responds to a socket".
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "\
import json, urllib.request, sys; \
body = json.load(urllib.request.urlopen('http://localhost:8000/health', timeout=3)); \
sys.exit(0 if body.get('status') == 'ok' else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
