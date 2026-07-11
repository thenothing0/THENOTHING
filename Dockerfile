# ════════════════════════════════════════════════
#  HYDRA — Multi-Stage Docker Build
# ════════════════════════════════════════════════

# ── Base image with all security tools ───────
FROM golang:1.22-bookworm AS tools-builder

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master


# ── Python base ──────────────────────────────
FROM python:3.12-slim-bookworm AS python-base

LABEL org.opencontainers.image.title="HYDRA Security Platform" \
      org.opencontainers.image.description="Autonomous AI Security Intelligence & Orchestration" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="THENOTHING Contributors" \
      org.opencontainers.image.source="https://github.com/thenothing-sec/hydra"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whatweb \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy Go-built tools
COPY --from=tools-builder /go/bin/subfinder /usr/local/bin/
COPY --from=tools-builder /go/bin/httpx /usr/local/bin/
COPY --from=tools-builder /go/bin/nuclei /usr/local/bin/
COPY --from=tools-builder /go/bin/katana /usr/local/bin/
COPY --from=tools-builder /go/bin/ffuf /usr/local/bin/
COPY --from=tools-builder /go/bin/gau /usr/local/bin/
COPY --from=tools-builder /go/bin/amass /usr/local/bin/

# Update Nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Install Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install additional Python security tools
RUN pip install --no-cache-dir wafw00f dirsearch

# Copy application code
COPY . .

# Create data directories and non-root user
RUN mkdir -p /app/data /app/logs /app/results /app/reports /app/wordlists \
    && groupadd -r hydra && useradd -r -g hydra -d /app -s /sbin/nologin hydra \
    && chown -R hydra:hydra /app/data /app/logs /app/results /app/reports /app/wordlists

# Download default wordlist if missing
RUN if [ ! -f /app/wordlists/common.txt ]; then \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    -o /app/wordlists/common.txt || echo "placeholder" > /app/wordlists/common.txt; \
    fi


# ── MCP Server target ───────────────────────
FROM python-base AS mcp-server
EXPOSE 8900
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8900/health')" || exit 1
USER hydra
CMD ["python", "-m", "hydra.mcp.http_server"]


# ── Coordinator target ───────────────────────
FROM python-base AS coordinator
ENV TARGET="example.com"
USER hydra
CMD python -m hydra.main --target "$TARGET"


# ── Worker target ────────────────────────────
FROM python-base AS worker
ENV TARGET="example.com"
USER hydra
CMD python -m hydra.main --target "$TARGET"


# ── Slim target (Python-only, no Go tools) ───
FROM python:3.12-slim-bookworm AS slim

LABEL org.opencontainers.image.title="HYDRA Security Platform (slim)" \
      org.opencontainers.image.description="Python-only HYDRA — no Go security binaries" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="THENOTHING Contributors"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data /app/logs /app/results /app/reports /app/wordlists \
    && groupadd -r hydra && useradd -r -g hydra -d /app -s /sbin/nologin hydra \
    && chown -R hydra:hydra /app/data /app/logs /app/results /app/reports /app/wordlists

USER hydra
CMD ["python", "-m", "hydra.mcp.http_server"]
