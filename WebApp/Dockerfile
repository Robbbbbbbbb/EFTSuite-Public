FROM python:3.11-slim-bookworm

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

# Set working directory
WORKDIR /app
COPY . /app

# Verify setup.sh exists (in nbis directory)
RUN if [ ! -f /app/nbis/setup.sh ]; then \
        echo "ERROR: setup.sh not found in /app/nbis. Please run 'docker build .' from the repository root."; \
        ls -la /app/nbis; \
        exit 1; \
    fi

# Build NBIS
# Ensure all scripts and configure files are executable before building
RUN find /app/nbis -type f -name "*.sh" -exec chmod +x {} + && \
    find /app/nbis -type f -name "configure" -exec chmod +x {} + && \
    cd /app/nbis && \
    ./setup.sh /usr/local --without-X11 && \
    make config && \
    make it && \
    make install LIBNBIS=no && \
    make clean

# Verify NBIS installation
RUN ls -l /usr/local/bin

# Add NBIS to PATH
ENV PATH="/usr/local/bin:${PATH}"

# Install Python dependencies
# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create directory for temp files
RUN mkdir -p /app/temp

# Expose port
EXPOSE 8080

# Command to run the application
# If the app fails, the container will stay running for debugging.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port 8080 || tail -f /dev/null"]
