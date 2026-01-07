# Production image for SENTINEL
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install runtime dependencies including graphics libraries for PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r scanner && useradd -r -g scanner scanner

# Set working directory
WORKDIR /app

# Copy dependency files
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY wordlists/ ./wordlists/
COPY config/ ./config/

# Create necessary directories
RUN mkdir -p /app/output/reports /app/output/logs /app/output/temp && \
    chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
