FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (curl for health check only)
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy requirements from edon_gateway directory (self-contained)
COPY edon_gateway/requirements.gateway.txt ./requirements.gateway.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.gateway.txt

# Copy the gateway application (edon_gateway directory) to /app/edon_gateway/
# This preserves the package structure for relative imports
COPY edon_gateway/ ./edon_gateway/

# Set PYTHONPATH so Python can find the edon_gateway package
ENV PYTHONPATH=/app

# Expose port (Render will set $PORT)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# Run gateway using the package path (edon_gateway.main:app)
CMD python -m uvicorn edon_gateway.main:app --host 0.0.0.0 --port ${PORT:-8000}
