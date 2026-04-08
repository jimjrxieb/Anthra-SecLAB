# DELIBERATELY INSECURE — runs as root, no healthcheck, no multi-stage
FROM python:3.11
# SECURITY: Add HEALTHCHECK instruction
# HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 8080
# Security: Run as non-root user (Hadolint DL3002, Checkov CKV_DOCKER_2)
RUN useradd --uid 10001 --no-create-home --shell /bin/false appuser
USER 10001

# Security: Health check for K8s liveness/readiness (Checkov CKV_DOCKER_3)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
