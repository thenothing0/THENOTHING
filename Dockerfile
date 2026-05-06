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

# Create data directories
RUN mkdir -p /app/data /app/logs /app/results /app/reports /app/wordlists

# Download default wordlist if missing
RUN if [ ! -f /app/wordlists/common.txt ]; then \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    -o /app/wordlists/common.txt || echo "placeholder" > /app/wordlists/common.txt; \
    fi


# ── MCP Server target ───────────────────────
FROM python-base AS mcp-server
EXPOSE 8900
CMD ["python", "-m", "hydra.mcp.http_server"]


# ── Coordinator target ───────────────────────
FROM python-base AS coordinator
ENV TARGET="example.com"
CMD python -m hydra.main --target "$TARGET"


# ── Worker target ────────────────────────────
FROM python-base AS worker
ENV TARGET="example.com"
CMD python -m hydra.main --target "$TARGET"
