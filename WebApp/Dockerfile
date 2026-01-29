# EFTSuite Secure Dockerfile
# Multi-stage build for smaller, more secure image

FROM python:3.11-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    cmake \
    git \
    libpng-dev \
    libjpeg-dev \
    libopenjp2-7-dev \
    libopenjp2-tools \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy NBIS source and build
COPY nbis /build/nbis

RUN find /build/nbis -type f -name "*.sh" -exec chmod +x {} + && \
    find /build/nbis -type f -name "configure" -exec chmod +x {} + && \
    cd /build/nbis && \
    ./setup.sh /build/nbis-install --without-X11 && \
    make config && \
    make it && \
    make install LIBNBIS=no DESTDIR=/build/nbis-install

# Final stage
FROM python:3.11-slim-bookworm

# Security: Create non-root user
RUN groupadd -r eftsuite && useradd -r -g eftsuite eftsuite

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpng16-16 \
    libjpeg62-turbo \
    libopenjp2-7 \
    libopenjp2-tools \
    zlib1g \
    # For secure delete
    coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Copy NBIS binaries from builder
COPY --from=builder /build/nbis-install/build/nbis-install/bin /usr/local/bin/

# Copy application files
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py /app/
COPY services /app/services/
COPY static /app/static/

# Create directories with proper permissions
RUN mkdir -p /app/temp /app/data && \
    chown -R eftsuite:eftsuite /app

# Security: Set restrictive permissions
RUN chmod 750 /app && \
    chmod 700 /app/temp /app/data && \
    chmod 640 /app/main.py && \
    chmod -R 750 /app/services && \
    chmod -R 755 /app/static

# Environment variables with secure defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    REQUIRE_AUTH=true \
    ALLOW_REGISTRATION=true \
    DEBUG=false \
    MAX_UPLOAD_SIZE_MB=50 \
    SESSION_TIMEOUT_HOURS=2

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Expose port
EXPOSE 8080

# Switch to non-root user
USER eftsuite

# Run with uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
