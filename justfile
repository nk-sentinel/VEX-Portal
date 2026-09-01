# VEX Portal task runner.
default:
    just --list

# No dev database container to start — the database is a SQLite file under
# backend/data/, and `just migrate` creates it. `just up` brings up the
# containerized API (vex-portal-api) behind Traefik at vex.shadow-lab.org;
# it uses its own volume, separate from the host-venv database `just
# dev-api`/`just migrate` use, since this project is single-replica by
# design and the two must never write the same SQLite file concurrently.

# --- Deploy ---
up:
    docker compose up -d --build

down:
    docker compose down

# --- Backend ---
install:
    cd backend && python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'

dev-api:
    cd backend && .venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
    cd backend && PYTHONPATH=. .venv/bin/pytest -q

lint:
    cd backend && .venv/bin/ruff check app tests && .venv/bin/mypy app

migrate:
    cd backend && .venv/bin/alembic upgrade head

# --- Frontend ---
# Port 4200 is occupied by an unrelated DAST-Portal `ng serve` on this host
# — 4201 avoids the collision (see the Task 3 report).
dev-web:
    cd web && npx ng serve --host 0.0.0.0 --port 4201
