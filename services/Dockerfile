# DELIBERATELY INSECURE — runs as root, no multi-stage, no healthcheck
FROM golang:1.22

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o log-ingest .

EXPOSE 9090
# Security: Run as non-root user (Hadolint DL3002, Checkov CKV_DOCKER_2)
RUN useradd --uid 10001 --no-create-home --shell /bin/false appuser
USER 10001

# Security: Health check for K8s liveness/readiness (Checkov CKV_DOCKER_3)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:9090/ || exit 1

CMD ["./log-ingest"]
