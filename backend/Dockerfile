# Multi-stage production Dockerfile for Ethio-SOAR (Waliya-IR) Backend, Workers & Migration Runner
FROM python:3.11-slim AS builder

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

FROM python:3.11-slim AS runner

# Dedicated unprivileged non-root user and group (UID/GID 10001)
RUN groupadd -g 10001 waliya && \
    useradd -u 10001 -g waliya -s /bin/bash -m waliya

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Copy application configuration, migrations, and source code
COPY --chown=waliya:waliya alembic.ini .
COPY --chown=waliya:waliya alembic/ alembic/
COPY --chown=waliya:waliya src/ src/

# Switch to unprivileged non-root user
USER waliya

EXPOSE 8000

# Default entrypoint runs FastAPI API server; overridden for worker or migration runner
CMD ["uvicorn", "waliya.main:app", "--host", "0.0.0.0", "--port", "8000"]
