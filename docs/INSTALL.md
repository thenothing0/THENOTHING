# Installation

## Prerequisites

- Python 3.10+ (3.12 recommended)
- Kali Linux (recommended) or any Linux with security tools
- Git

## Method 1: Source (development)

```bash
git clone https://github.com/thenothing-sec/hydra.git
cd hydra
pip install -e ".[dev]"
```

## Method 2: pip

```bash
pip install hydra-security
```

With optional extras:

```bash
pip install "hydra-security[ai]"          # OpenAI/Anthropic/embeddings
pip install "hydra-security[dashboard]"   # FastAPI dashboard
pip install "hydra-security[browser]"     # Playwright browser crawling
pip install "hydra-security[all]"         # Everything
```

### Available extras

| Extra | Packages | Purpose |
|-------|----------|---------|
| `dev` | pytest, ruff, build, twine | Development and testing |
| `ai` | openai, anthropic, sentence-transformers | AI-powered analysis |
| `dashboard` | fastapi, uvicorn, websockets | Web dashboard |
| `vector` | chromadb | Vector/semantic memory |
| `browser` | playwright | Headless browser crawling |
| `docs` | mkdocs, mkdocs-material | Documentation site |
| `all` | All of the above (except dev) | Full installation |

## Method 3: Docker

```bash
# Full image with Go security tools
docker build --target mcp-server -t hydra:mcp .

# Slim image (Python only, no Go tools)
docker build --target slim -t hydra:slim .

# Run MCP server
docker run -p 8900:8900 hydra:mcp

# Run with custom target
docker run -e TARGET=example.com hydra:coordinator
```

## Method 4: Kali Linux (native)

On Kali, most security tools are pre-installed:

```bash
git clone https://github.com/thenothing-sec/hydra.git
cd hydra
pip install -e ".[dev]"

# Verify tool availability
python -m hydra --check-tools
```

## Verifying installation

```bash
# Check version
python -c "from hydra import __version__; print(__version__)"

# Check CLI
hydra-engine --help

# Check TUI
hydra --help

# Check MCP server
python mcp_server.py --help

# Check available security tools
python -m hydra --check-tools
```

## Security tools

HYDRA works best with these tools installed (all included in Kali Linux):

- **Recon**: subfinder, amass, httpx, katana, gau, hakrawler, dnsx
- **Scanning**: nuclei, sqlmap, dalfox, gxss, nmap
- **Fuzzing**: ffuf, dirsearch, feroxbuster
- **Fingerprinting**: whatweb, wafw00f
- **Takeover**: subzy

Install Go-based tools:

```bash
python -m hydra --install-tools
```
