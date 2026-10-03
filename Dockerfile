# =============================================================================
# SENTINEL — Security Platform
# Production-hardened multi-stage Dockerfile
# =============================================================================

FROM python:3.11-slim AS base

# Labels for container metadata (OCI standard)
LABEL org.opencontainers.image.title="SENTINEL" \
      org.opencontainers.image.description="Red team and blue team security platform" \
      org.opencontainers.image.version="6.0.0" \
      org.opencontainers.image.vendor="SENTINEL Security" \
      org.opencontainers.image.source="https://github.com/halilberkayy/SENTINEL" \
      org.opencontainers.image.licenses="MIT"

# =============================================================================
# Stage 1: Builder - install dependencies
# =============================================================================
FROM base AS builder

# Install build dependencies (needed for some Python packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy dependency files first (layer caching)
COPY requirements.txt .

# Install Python dependencies to a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Stage 2: Production - minimal runtime image
# =============================================================================
FROM base AS production

# Set security-focused environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Prevent Python from writing .pyc files in container
    PYTHONHASHSEED=random \
    # Run in production mode
    ENVIRONMENT=production

# Install runtime dependencies only (no compilers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    shared-mime-info \
    # Security: install dumb-init for proper signal handling
    dumb-init \
    && rm -rf /var/lib/apt/lists/* \
    # Security: remove apt cache and lists to reduce attack surface
    && apt-get purge -y --auto-remove \
    && rm -rf /var/cache/apt/*

# Create non-root user with specific UID/GID
RUN groupadd -r -g 1001 scanner && \
    useradd -r -u 1001 -g scanner -s /usr/sbin/nologin scanner

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code with proper ownership
COPY --chown=scanner:scanner src/ ./src/
COPY --chown=scanner:scanner wordlists/ ./wordlists/
COPY --chown=scanner:scanner config/ ./config/
COPY --chown=scanner:scanner web/ ./web/
COPY --chown=scanner:scanner web_app.py ./
COPY --chown=scanner:scanner scanner.py ./

# Create necessary directories with proper permissions
RUN mkdir -p /app/output/reports /app/output/logs /app/output/temp && \
    chown -R scanner:scanner /app/output

# Security: make application files read-only
RUN chmod -R 555 /app/src /app/wordlists /app/config /app/web && \
    chmod 555 /app/web_app.py /app/scanner.py

# Switch to non-root user
USER scanner

# Expose port
EXPOSE 8000

# Health check with proper timeout
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Use dumb-init as PID 1 for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Default command
CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
