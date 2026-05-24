# Ghost Security Platform — Production Dockerfile
# Multi-stage build: deps → app → runtime
# ─────────────────────────────────────────

FROM python:3.11-slim AS base

LABEL org.opencontainers.image.title="Ghost Security Platform"
LABEL org.opencontainers.image.version="2.2"
LABEL org.opencontainers.image.description="AI-native AppSec platform — defensive security only"

# ── System dependencies ────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Non-root user ──────────────────────────────────────────────────────────────
RUN useradd -m -u 1001 ghost && mkdir -p /app /app/data /app/ghost_reports /app/memory
WORKDIR /app

# ── Python deps (cached layer) ────────────────────────────────────────────────
FROM base AS deps
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir semgrep bandit || true

# ── Application source ────────────────────────────────────────────────────────
FROM deps AS runtime
COPY --chown=ghost:ghost . .

# Ensure writable dirs
RUN chown -R ghost:ghost /app/data /app/ghost_reports /app/memory

USER ghost

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Graceful startup with 2 workers; tune with WORKERS env var
CMD ["sh", "-c", "python3 -m uvicorn api.server:app \
     --host 0.0.0.0 \
     --port 8000 \
     --workers ${WORKERS:-2} \
     --log-level ${LOG_LEVEL:-info} \
     --timeout-keep-alive 30"]
