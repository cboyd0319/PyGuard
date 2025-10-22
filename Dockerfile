# PyGuard Docker Image
# Provides a containerized environment for running PyGuard

FROM python:3.13.9-slim

LABEL maintainer="Chad Boyd <your.email@example.com>"
LABEL description="PyGuard - Python QA and Auto-Fix Tool"
LABEL version="0.4.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY pyproject.toml setup.py ./
COPY README.md LICENSE ./

# Install PyGuard
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# Copy application code
COPY pyguard/ ./pyguard/
COPY config/ ./config/
COPY docs/ ./docs/

# Create directories for logs and backups
RUN mkdir -p /app/logs /app/backups

# Set up volume mount points
VOLUME ["/code", "/app/logs", "/app/backups"]

# Set default command
ENTRYPOINT ["pyguard"]
CMD ["--help"]

# Usage:
# Build: docker build -t pyguard .
# Run:   docker run -v $(pwd):/code pyguard /code
