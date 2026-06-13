# SKILL.md — VibeLock Conventions & Project Knowledge

## Stack
- **Language:** Python 3.11+
- **Framework:** FastAPI (ingestion), Celery + Redis (async workers)
- **Database:** Supabase (PostgreSQL)
- **LLM:** DeepSeek-Coder (via API) for semantic scanning + patch generation
- **Testing:** pytest, pytest-asyncio, pytest-cov
- **Linting:** ruff, mypy
- **Container:** Docker + docker-compose

## Coding Conventions
- Type hints on ALL function signatures (mypy strict mode)
- Async/await for all I/O (FastAPI, DB, HTTP)
- Pydantic v2 models for all request/response schemas
- Single-file modules until they exceed 300 lines, then split
- No print() — use structlog for all logging
- Environment variables via pydantic-settings, never hardcoded

## Branch Strategy
- `main` — production-ready, protected
- `fix` — active development (we work here)
- Feature branches: `feature/<task-id>-<short-desc>`

## Testing
- Run: `pytest tests/ -v --cov=src --cov-report=term-missing`
- Unit tests in `tests/unit/`, integration in `tests/integration/`
- Every endpoint needs at least: happy path, auth failure, malformed input

## We DON'T
- Use print() or root loggers — structlog only
- Hardcode secrets, tokens, or URLs
- Modify package-lock.json, pyproject.toml deps without explicit task scope
- Skip type hints
- Self-grade — verifier agent always checks implementer's work

## Architecture Rules
- Ingestion layer must respond to webhooks in <10s (GitHub timeout)
- Scanner runs async via Celery workers
- Remediation agent capped at 3 attempts per vulnerability
- Token sanitizer runs BEFORE any code sent to external LLM
- Atomic scoping: agent only touches files with identified vulns