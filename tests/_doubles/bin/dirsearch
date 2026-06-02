#!/usr/bin/env python3
"""
Fake security-tool dispatcher (Pillar 4 — Security Tool Simulation Harness).

Why this exists
---------------
Mitigates Risk #2 (the MCP subprocess boundary was untested) and Risk #3
(no safe way to exercise tool execution). The real tools (subfinder, nuclei,
sqlmap, …) require Kali + network + a live target, so they cannot run in CI.

This single script is copied to each tool name (subfinder, httpx, nuclei, …)
under tests/_doubles/bin/. When the harness prepends that directory to PATH,
mcp_server._run()'s `shutil.which(binary)` resolves THIS file, and the entire
tool pipeline executes end-to-end — real subprocess, real argv, real shell=False
behavior — but with deterministic, offline output.

It dispatches on its own invoked name (argv[0]) and emits canned, deterministic
stdout, then exits 0. It deliberately does NOT read stdin (so it never blocks
whether or not the caller supplied input).
"""

import json
import os
import sys

# Deterministic, parseable canned output keyed by tool name.
# Output shapes match what mcp_server's parsers expect.
_SUBS = "api.example.com\nwww.example.com\ndev.example.com\n"
_URLS = (
    "https://example.com/\n"
    "https://example.com/login\n"
    "https://example.com/api/v1/users?id=1\n"
)
_NUCLEI = "\n".join([
    json.dumps({
        "template-id": "tech-detect",
        "info": {"name": "Technology Detection", "severity": "info",
                 "description": "Detected server technology", "reference": []},
        "host": "https://example.com", "matched-at": "https://example.com",
        "type": "http", "matcher-name": "nginx",
    }),
    json.dumps({
        "template-id": "misconfig-cors",
        "info": {"name": "Permissive CORS", "severity": "medium",
                 "description": "CORS allows arbitrary origin", "reference": []},
        "host": "https://example.com", "matched-at": "https://example.com/api",
        "type": "http", "matcher-name": "",
    }),
]) + "\n"


def emit(name: str) -> int:
    if name in ("subfinder", "amass"):
        sys.stdout.write(_SUBS)
    elif name in ("katana", "gau", "hakrawler"):
        sys.stdout.write(_URLS)
    elif name == "httpx":
        sys.stdout.write(
            "https://api.example.com [200] [API Gateway]\n"
            "https://www.example.com [200] [Example Home]\n"
        )
    elif name in ("nuclei",):
        sys.stdout.write(_NUCLEI)
    elif name == "whatweb":
        sys.stdout.write(
            "https://example.com [200 OK] HTTPServer[nginx], "
            "Country[UNITED STATES][US], nginx\n"
        )
    elif name == "wafw00f":
        sys.stdout.write(
            "[+] The site https://example.com is behind Cloudflare "
            "(Cloudflare Inc.) WAF.\n"
        )
    elif name == "nmap":
        sys.stdout.write(
            "Starting Nmap\nNmap scan report for example.com (93.184.216.34)\n"
            "PORT    STATE SERVICE VERSION\n"
            "80/tcp  open  http    nginx\n443/tcp open  https   nginx\n"
        )
    elif name == "ffuf":
        sys.stdout.write("admin\nlogin\napi\n")
    elif name == "dirsearch":
        sys.stdout.write(json.dumps({
            "results": [{"path": "/admin", "status": 403},
                        {"path": "/login", "status": 200}]
        }))
    elif name == "sqlmap":
        sys.stdout.write(
            "sqlmap identified the following injection point(s):\n"
            "Parameter: id (GET)\n    Type: boolean-based blind\n"
        )
    elif name == "dalfox":
        sys.stdout.write(json.dumps([
            {"type": "V", "severity": "high", "param": "q",
             "data": "https://example.com/?q=<script>"}
        ]))
    elif name == "gxss":
        sys.stdout.write("https://example.com/?q=FUZZ\n")
    elif name == "dnsx":
        sys.stdout.write("example.com [A] [93.184.216.34]\n")
    else:
        sys.stdout.write("")
    return 0


if __name__ == "__main__":
    sys.exit(emit(os.path.basename(sys.argv[0])))
