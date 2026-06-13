# VibeLock — Multi-stage Dockerfile
FROM python:3.11-slim AS base

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]"

COPY src/ src/
COPY config/ config/

# --- Ingestion target ---
FROM base AS ingestion
CMD ["uvicorn", "src.ingestion.webhook_gateway:app", "--host", "0.0.0.0", "--port", "8000"]

# --- Scanner target ---
FROM base AS scanner
CMD ["celery", "-A", "src.scanner.worker", "worker", "--loglevel=info", "--concurrency=4"]

# --- Remediation target ---
FROM base AS remediation
CMD ["celery", "-A", "src.remediation.worker", "worker", "--loglevel=info", "--concurrency=2"]