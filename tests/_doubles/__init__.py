"""Security-tool doubles (Pillar 4).

Provides the path to the directory of fake tool binaries and a helper to put
them on PATH so the real mcp_server._run() subprocess pipeline resolves them.
"""

from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent / "bin"

# Tool names we provide deterministic fakes for (one executable per name).
FAKE_TOOLS = [
    "subfinder", "amass", "httpx", "katana", "gau", "hakrawler", "nuclei",
    "whatweb", "wafw00f", "nmap", "ffuf", "dirsearch", "sqlmap", "dalfox",
    "gxss", "dnsx",
]


def install_fakes(monkeypatch) -> Path:
    """Prepend the fake-bin directory to PATH for the duration of a test."""
    monkeypatch.setenv("PATH", f"{BIN_DIR}{':'}{__import__('os').environ.get('PATH', '')}")
    return BIN_DIR
