FROM chromadb/chroma@sha256:3ce58229cf62ab1450e3120f31b613bf19037d896f25c8469d2be469aed2a155

# Add health check endpoint
COPY health-check.py /app/health-check.py

# Install curl for health checks
USER root
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Create chroma user and group if they don't exist
RUN groupadd -r chroma || true
RUN useradd -r -g chroma -s /bin/false chroma || true

# Set permissions for directories that exist
RUN chown -R chroma:chroma /app 2>/dev/null || true
RUN mkdir -p /chroma && chown -R chroma:chroma /chroma 2>/dev/null || true

USER chroma

EXPOSE 8000

# Security: Health check for K8s liveness/readiness (Checkov CKV_DOCKER_3)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1

CMD ["chroma", "run", "--host", "0.0.0.0", "--port", "8000"]
