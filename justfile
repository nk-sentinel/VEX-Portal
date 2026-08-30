# Exploitability Assessment Portal task runner.
default:
    just --list

# No dev infrastructure to start: the database is a SQLite file under
# backend/data/. `just migrate` creates it.

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
dev-web:
    cd web && npx ng serve --host 0.0.0.0 --port 4200
