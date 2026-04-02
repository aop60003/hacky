# Dockerfile
FROM python:3.12-slim

LABEL maintainer="VIBEE-Hacker Contributors"
LABEL version="2.2.0"
LABEL description="Security vulnerability scanner with 138 plugins"

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git nmap curl dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy and install
COPY pyproject.toml README.md LICENSE ./
COPY vibee_hacker/ ./vibee_hacker/

RUN pip install --no-cache-dir -e "." && \
    pip install --no-cache-dir playwright && \
    playwright install --with-deps chromium

# Create non-root user
RUN useradd -m -s /bin/bash scanner
USER scanner

EXPOSE 8000

ENTRYPOINT ["vibee-hacker"]
CMD ["--help"]
