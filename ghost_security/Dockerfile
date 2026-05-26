# Ghost Security Platform — Production Dockerfile
# Multi-stage build: builder → runtime
# ──────────────────────────────────────

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

LABEL stage="builder"

# System build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Install Python dependencies into a prefix we can copy wholesale
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt && \
    pip install --no-cache-dir --prefix=/install semgrep bandit || true

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="Ghost Security Platform"
LABEL org.opencontainers.image.version="13.0"
LABEL org.opencontainers.image.description="AI-native AppSec platform — defensive security only"
LABEL org.opencontainers.image.source="https://github.com/ton-blockchain/ton"

# Minimal runtime system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -m -u 1001 -s /bin/bash ghostuser && \
    mkdir -p /app/data /app/ghost_reports /app/memory /app/.ghost

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source (owned by ghostuser)
COPY --chown=ghostuser:ghostuser . .

# Ensure writable runtime directories
RUN chown -R ghostuser:ghostuser /app/data /app/ghost_reports /app/memory /app/.ghost

# Drop to non-root
USER ghostuser

EXPOSE 8000

# Lightweight health check via the CLI status command
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD python ghost_cli_main.py status || exit 1

# Default: run the API server via uvicorn
CMD ["sh", "-c", \
     "python ghost_cli_main.py serve \
      --host 0.0.0.0 \
      --port 8000 \
      --workers ${WORKERS:-2} \
      --log-level ${LOG_LEVEL:-info}"]
