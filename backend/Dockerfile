# Multi-stage Dockerfile for GridPulse FastAPI Backend

# ==========================================
# Stage 1: Build virtual environment & dependencies
# ==========================================
FROM python:3.11-slim-bookworm AS builder

# Set Python build environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install required build tools for C extensions (e.g., psycopg2, asyncpg)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create isolated virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build

# Copy and install python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt


# ==========================================
# Stage 2: Lean runtime image
# ==========================================
FROM python:3.11-slim-bookworm AS runner

# Set Python runtime environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

# Install minimal runtime libraries (libpq for postgres client, curl for health check)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root system user and group
RUN groupadd -g 1001 gridpulse && \
    useradd -u 1001 -g gridpulse -s /bin/bash -m gridpulse

WORKDIR /app

# Copy pre-built virtual environment from builder stage
COPY --from=builder --chown=gridpulse:gridpulse /opt/venv /opt/venv

# Copy application configuration and codebase
COPY --chown=gridpulse:gridpulse alembic.ini .
COPY --chown=gridpulse:gridpulse alembic ./alembic
COPY --chown=gridpulse:gridpulse app ./app
COPY --chown=gridpulse:gridpulse entrypoint.sh ./entrypoint.sh

RUN chmod +x /app/entrypoint.sh

USER gridpulse

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
