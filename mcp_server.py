#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  HYDRA MCP Server — Security Tool Execution Layer           ║
║  Compatible with: Claude Code, Cursor, Cline, Windsurf      ║
║  Usage: Add to your AI coding agent's MCP config             ║
╚══════════════════════════════════════════════════════════════╝

This MCP server gives any AI coding agent direct access to
real security tools via the Model Context Protocol.

Project MCP config (register this file):
  - .mcp.json (Claude Code)
  - .cursor/mcp.json (Cursor)
  - cline_mcp_settings.json (Cline)
  - .claude/settings.json — enabledMcpjsonServers: ["hydra-security"]

Supported AI agents:
  - Claude Code:  auto-detected via .mcp.json
  - Cursor:       add to .cursor/mcp.json
  - Cline:        add to cline_mcp_settings.json
  - Windsurf:     add to ~/.windsurf/mcp.json
  - Any MCP-compatible client

All tools are REAL — executed via subprocess. No mocking.
"""

import json
import os
import re as _re
import shutil
import subprocess
import sys
import sqlite3
import time
from pathlib import Path
from typing import List, Optional

from mcp.server.fastmcp import FastMCP

# ──────────────────────────────────────────────
#  Server Setup
# ──────────────────────────────────────────────

mcp = FastMCP("hydra-security")

# Paths
BASE_DIR = Path(__file__).parent
WORDLISTS_DIR = BASE_DIR / "wordlists"
RESULTS_DIR = BASE_DIR / "results"
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"
LEARNING_DB = DATA_DIR / "learning.db"

# Maximum output size to prevent MCP protocol overload
MAX_OUTPUT_CHARS = 500_000

# Tor proxy mode — wraps all tool execution through proxychains4
USE_TOR = os.environ.get("HYDRA_TOR", "0") == "1"
PROXYCHAINS_BIN = shutil.which("proxychains4") or shutil.which("proxychains")

for d in [WORDLISTS_DIR, RESULTS_DIR, REPORTS_DIR, DATA_DIR]:
    d.mkdir(parents=True, exist_ok=True)


# ──────────────────────────────────────────────
#  Observability + run recording (Pillars 7 & 8)
#  Guarded imports: the MCP server must keep working
#  even if the `hydra` package is unavailable.
# ──────────────────────────────────────────────
try:
    from hydra.observability import metrics as _metrics
except Exception:  # pragma: no cover - optional dependency
    _metrics = None

try:
    from hydra.observability.run_recorder import record_tool_event as _record_tool_event
except Exception:  # pragma: no cover - optional dependency
    _record_tool_event = None


# ──────────────────────────────────────────────
#  Input validation (Pillar 3 — argument-injection defense)
#
#  _run() executes via subprocess with a LIST and shell=False, so
#  classic SHELL injection is already closed. The remaining risk is
#  ARGUMENT/OPTION injection: a user-supplied value that lands in its
#  own argv slot (the positional args of gau/whatweb/wafw00f/nmap) and
#  starts with '-' is parsed by the tool as a FLAG (e.g. nmap
#  "--script=evil"). Whitespace, newlines and shell metacharacters
#  also have no place in a hostname or URL. Policy: reject such values
#  at the boundary BEFORE the command is ever built.
# ──────────────────────────────────────────────

_HOST_RE = _re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:\-]*[A-Za-z0-9])?$")
_HOST_CIDR_RE = _re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:\-/]*[A-Za-z0-9])?$")
# URLs: must be http(s); '&', '?', '=' are legitimate query syntax and are
# allowed (harmless under shell=False). Whitespace/quotes/backtick/redirection
# characters are rejected.
_URL_RE = _re.compile(r"^https?://[^\s`'\"\\<>|;]+$", _re.IGNORECASE)
_DNS_RECORD_TYPES = {"a", "aaaa", "cname", "mx", "ns", "txt", "soa", "ptr", "srv", "caa", "any"}


def _err(msg: str) -> dict:
    """Boundary-rejection result, shaped like a _run() failure."""
    return {"success": False, "error": msg, "output": "", "rejected": True}


def _validate_host(value: str, allow_cidr: bool = False) -> Optional[dict]:
    """Return an error dict if `value` is not a clean hostname/IP, else None."""
    v = (value or "").strip()
    if not v:
        return _err("Empty host/domain value")
    if v.startswith("-"):
        return _err(f"Rejected '{value}': leading '-' looks like a command-line flag, not a host")
    rx = _HOST_CIDR_RE if allow_cidr else _HOST_RE
    if not rx.match(v):
        return _err(f"Rejected '{value}': not a valid hostname/IP "
                    "(whitespace and shell metacharacters are not allowed)")
    return None


def _validate_url(value: str) -> Optional[dict]:
    """Return an error dict if `value` is not a clean http(s) URL, else None."""
    v = (value or "").strip()
    if not v:
        return _err("Empty URL value")
    if v.startswith("-"):
        return _err(f"Rejected '{value}': leading '-' looks like a flag, not a URL")
    if not _URL_RE.match(v):
        return _err(f"Rejected '{value}': must be an http(s) URL with no whitespace or shell metacharacters")
    return None


def _validate_block(value: str, kind: str = "any") -> Optional[dict]:
    """Validate a newline-delimited block of hosts/URLs (stdin/file inputs)."""
    lines = [ln.strip() for ln in (value or "").splitlines() if ln.strip()]
    if not lines:
        return _err("Empty target list")
    for line in lines:
        if kind == "host":
            e = _validate_host(line)
        elif kind == "url":
            e = _validate_url(line)
        else:  # auto: URL if it has a scheme, otherwise host
            e = _validate_url(line) if "://" in line else _validate_host(line)
        if e:
            return _err(f"Invalid entry '{line}': {e['error']}")
    return None


def _finalize(binary: str, cmd: List[str], result: dict, elapsed: float = 0.0) -> dict:
    """Record metrics + run-event for an execution, then return the result.

    Centralises Pillar 8 (observability) and Pillar 7 (replay) so every exit
    path of _run() is instrumented exactly once. Best-effort: telemetry never
    breaks a live operation.
    """
    if _metrics is not None:
        try:
            _metrics.inc_counter("tool_executions_total", labels={"tool": binary})
            if not result.get("success"):
                _metrics.inc_counter("tool_failures_total", labels={"tool": binary})
            _metrics.observe_histogram(
                "tool_latency_seconds",
                float(result.get("elapsed_seconds", elapsed) or elapsed),
                labels={"tool": binary},
            )
        except Exception:  # pragma: no cover
            pass
    if _record_tool_event is not None:
        try:
            _record_tool_event(binary, cmd, result)
        except Exception:  # pragma: no cover
            pass
    return result


def _run(cmd: List[str], timeout: int = 120, stdin_data: Optional[str] = None) -> dict:
    """Execute a real system tool via subprocess. No mocking. shell=False."""
    binary = cmd[0]
    path = shutil.which(binary)
    if not path:
        return _finalize(binary, cmd, {
            "success": False,
            "error": f"Tool '{binary}' not installed. Install it first.",
            "output": "",
        })

    if USE_TOR and PROXYCHAINS_BIN:
        cmd = [PROXYCHAINS_BIN, "-q"] + cmd

    print(f"[HYDRA] {'[TOR] ' if USE_TOR else ''}Running: {' '.join(cmd)}", file=sys.stderr)
    start = time.time()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_data,
        )
        elapsed = round(time.time() - start, 2)
        stdout = proc.stdout
        stderr = proc.stderr

        # Truncate oversized output to prevent MCP protocol overload
        truncated = False
        if len(stdout) > MAX_OUTPUT_CHARS:
            stdout = stdout[:MAX_OUTPUT_CHARS] + f"\n... [TRUNCATED — {len(proc.stdout)} total chars]"
            truncated = True

        return _finalize(binary, cmd, {
            "success": proc.returncode == 0,
            "output": stdout,
            "stderr": stderr[:50000] if len(stderr) > 50000 else stderr,
            "return_code": proc.returncode,
            "elapsed_seconds": elapsed,
            "truncated": truncated,
        }, elapsed)
    except subprocess.TimeoutExpired:
        return _finalize(binary, cmd,
                         {"success": False, "error": f"Timeout after {timeout}s", "output": ""},
                         round(time.time() - start, 2))
    except Exception as e:
        return _finalize(binary, cmd,
                         {"success": False, "error": str(e), "output": ""},
                         round(time.time() - start, 2))


# ══════════════════════════════════════════════
#  RECON TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
def subfinder_scan(domain: str, silent: bool = True) -> str:
    """
    Enumerate subdomains for a target domain using subfinder.
    Fast passive subdomain discovery.

    Args:
        domain: Target domain (e.g., "example.com")
        silent: If True, only output subdomains
    """
    err = _validate_host(domain)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["subfinder", "-d", domain]
    if silent:
        cmd.append("-silent")
    result = _run(cmd, timeout=180)
    if result["success"]:
        subs = [ln.strip() for ln in result["output"].strip().split("\n") if ln.strip()]
        return json.dumps({"subdomains": subs, "count": len(subs)}, indent=2)
    return json.dumps(result, indent=2)


@mcp.tool()
def amass_enum(domain: str, passive: bool = True) -> str:
    """
    Enumerate subdomains using OWASP Amass. More thorough than subfinder
    but slower. Use passive mode for stealth.

    Args:
        domain: Target domain (e.g., "example.com")
        passive: If True, use passive recon only (no active DNS queries)
    """
    err = _validate_host(domain)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["amass", "enum"]
    if passive:
        cmd.append("-passive")
    cmd.extend(["-d", domain])
    result = _run(cmd, timeout=300)
    if result["success"]:
        subs = [ln.strip() for ln in result["output"].strip().split("\n") if ln.strip()]
        return json.dumps({"subdomains": subs, "count": len(subs)}, indent=2)
    return json.dumps(result, indent=2)


@mcp.tool()
def httpx_probe(targets: str, status_code: bool = True, title: bool = True,
                tech_detect: bool = False, follow_redirects: bool = True) -> str:
    """
    Probe URLs/domains for live HTTP services using httpx.
    Pass multiple targets separated by newlines.

    Args:
        targets: One or more URLs/domains, one per line
        status_code: Show HTTP status codes
        title: Show page titles
        tech_detect: Detect web technologies
        follow_redirects: Follow HTTP redirects
    """
    err = _validate_block(targets, kind="any")
    if err:
        return json.dumps(err, indent=2)
    cmd = ["httpx", "-silent"]
    if status_code:
        cmd.append("-sc")
    if title:
        cmd.append("-title")
    if tech_detect:
        cmd.append("-td")
    if follow_redirects:
        cmd.append("-fr")

    result = _run(cmd, timeout=120, stdin_data=targets)
    return json.dumps(result, indent=2)


@mcp.tool()
def katana_crawl(target: str, depth: int = 3, js_crawl: bool = False) -> str:
    """
    Crawl a target website to discover endpoints, URLs, and JS files.
    Uses Katana web crawler.

    Args:
        target: Target URL (e.g., "https://example.com")
        depth: Crawl depth (1-5)
        js_crawl: Also crawl JavaScript files for endpoints
    """
    err = _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["katana", "-u", target, "-silent", "-d", str(min(depth, 5))]
    if js_crawl:
        cmd.append("-jc")
    result = _run(cmd, timeout=180)
    if result["success"]:
        urls = [ln.strip() for ln in result["output"].strip().split("\n") if ln.strip()]
        return json.dumps({"endpoints": urls, "count": len(urls)}, indent=2)
    return json.dumps(result, indent=2)


@mcp.tool()
def gau_urls(domain: str) -> str:
    """
    Fetch known URLs for a domain from Wayback Machine, Common Crawl,
    and other sources using gau (Get All URLs).

    Args:
        domain: Target domain (e.g., "example.com")
    """
    err = _validate_host(domain)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["gau", domain]
    result = _run(cmd, timeout=120)
    if result["success"]:
        urls = [ln.strip() for ln in result["output"].strip().split("\n") if ln.strip()]
        return json.dumps({"urls": urls, "count": len(urls)}, indent=2)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  VULNERABILITY SCANNING TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
def nuclei_scan(target: str, severity: str = "low,medium,high,critical",
                tags: str = "", templates: str = "",
                rate_limit: int = 150) -> str:
    """
    Run Nuclei vulnerability scanner against a target.
    Uses community templates to detect known vulnerabilities, misconfigurations,
    exposed panels, default credentials, and more.

    Args:
        target: Target URL (e.g., "https://example.com")
        severity: Comma-separated severities to scan for (low,medium,high,critical)
        tags: Comma-separated template tags to filter (e.g., "cve,sqli,xss")
        templates: Specific template path/ID to use
        rate_limit: Maximum requests per second
    """
    err = _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent",
           "-severity", severity, "-rl", str(rate_limit)]
    if tags:
        cmd.extend(["-tags", tags])
    if templates:
        cmd.extend(["-t", templates])

    result = _run(cmd, timeout=600)
    if result["success"]:
        findings = []
        for line in result["output"].strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "template_id": data.get("template-id", ""),
                    "name": data.get("info", {}).get("name", ""),
                    "severity": data.get("info", {}).get("severity", ""),
                    "host": data.get("host", ""),
                    "matched_at": data.get("matched-at", ""),
                    "type": data.get("type", ""),
                    "description": data.get("info", {}).get("description", ""),
                    "reference": data.get("info", {}).get("reference", []),
                    "matcher_name": data.get("matcher-name", ""),
                })
            except json.JSONDecodeError:
                findings.append({"raw": line})
        return json.dumps({
            "findings": findings, "count": len(findings),
            "target": target, "severity_filter": severity,
        }, indent=2)
    return json.dumps(result, indent=2)


@mcp.tool()
def nuclei_scan_list(targets: str, severity: str = "medium,high,critical",
                     tags: str = "", rate_limit: int = 100) -> str:
    """
    Run Nuclei against multiple targets at once. Pass targets one per line.

    Args:
        targets: Multiple target URLs, one per line
        severity: Comma-separated severity filter
        tags: Template tag filter
        rate_limit: Max requests per second
    """
    err = _validate_block(targets, kind="any")
    if err:
        return json.dumps(err, indent=2)
    # Write targets to temp file
    targets_file = RESULTS_DIR / f"targets_{int(time.time())}.txt"
    targets_file.write_text(targets.strip())

    cmd = ["nuclei", "-l", str(targets_file), "-jsonl", "-silent",
           "-severity", severity, "-rl", str(rate_limit)]
    if tags:
        cmd.extend(["-tags", tags])

    result = _run(cmd, timeout=900)
    targets_file.unlink(missing_ok=True)

    if result["success"]:
        findings = []
        for line in result["output"].strip().split("\n"):
            if not line.strip():
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                findings.append({"raw": line})
        return json.dumps({"findings": findings, "count": len(findings)}, indent=2)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  FUZZING TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
def ffuf_fuzz(url: str, wordlist: str = "", match_codes: str = "200,301,302,403",
              method: str = "GET", headers: str = "",
              fuzz_mode: str = "directory") -> str:
    """
    Fuzz web endpoints using ffuf. The FUZZ keyword marks the injection point.

    Args:
        url: Target URL with FUZZ keyword (e.g., "https://example.com/FUZZ")
             If no FUZZ keyword, it appends /FUZZ automatically for directory fuzzing.
        wordlist: Path to wordlist file. Uses default common.txt if empty.
        match_codes: HTTP status codes to match (comma-separated)
        method: HTTP method (GET, POST, etc.)
        headers: Custom headers as "Header1:Value1,Header2:Value2"
        fuzz_mode: "directory" adds /FUZZ to URL, "parameter" for param fuzzing
    """
    err = _validate_url(url)
    if err:
        return json.dumps(err, indent=2)
    if "FUZZ" not in url:
        if fuzz_mode == "directory":
            url = url.rstrip("/") + "/FUZZ"
        else:
            url = url + "?FUZZ=test"

    wl = wordlist or str(WORDLISTS_DIR / "common.txt")
    if not Path(wl).exists():
        return json.dumps({"error": f"Wordlist not found: {wl}. Download one first."})

    cmd = ["ffuf", "-u", url, "-w", wl, "-mc", match_codes,
           "-X", method, "-s"]

    if headers:
        for h in headers.split(","):
            cmd.extend(["-H", h.strip()])

    result = _run(cmd, timeout=300)
    return json.dumps(result, indent=2)


@mcp.tool()
def dirsearch_scan(url: str, extensions: str = "php,asp,aspx,jsp,html,js",
                   threads: int = 25) -> str:
    """
    Brute-force directories and files on a web server using dirsearch.

    Args:
        url: Target URL (e.g., "https://example.com")
        extensions: File extensions to search for (comma-separated)
        threads: Number of concurrent threads
    """
    err = _validate_url(url)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["dirsearch", "-u", url, "-e", extensions, "-t", str(threads), "-q",
           "--format=json"]
    result = _run(cmd, timeout=300)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  FINGERPRINTING & DETECTION TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
def whatweb_detect(target: str, aggression: int = 1) -> str:
    """
    Detect web technologies, CMS, frameworks, and server software
    running on a target using WhatWeb.

    Args:
        target: Target URL (e.g., "https://example.com")
        aggression: Scan intensity (1=stealthy, 3=aggressive)
    """
    err = _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["whatweb", target, f"--aggression={aggression}", "--color=never"]
    result = _run(cmd, timeout=60)
    return json.dumps(result, indent=2)


@mcp.tool()
def wafw00f_detect(target: str) -> str:
    """
    Detect Web Application Firewalls (WAFs) protecting a target.
    Identifies specific WAF products (Cloudflare, Akamai, etc.)

    Args:
        target: Target URL (e.g., "https://example.com")
    """
    err = _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["wafw00f", target]
    result = _run(cmd, timeout=60)
    return json.dumps(result, indent=2)


@mcp.tool()
def nmap_scan(target: str, ports: str = "1-1000", scan_type: str = "service",
              scripts: str = "") -> str:
    """
    Network port scanning and service detection using nmap.

    Args:
        target: Target hostname or IP
        ports: Port range (e.g., "80,443", "1-1000", "top1000")
        scan_type: "quick" (SYN scan), "service" (version detection), "full" (all ports)
        scripts: Nmap scripts to run (e.g., "http-headers,ssl-cert")
    """
    # nmap takes a host/IP/CIDR positional arg — a value beginning with '-'
    # would be parsed as a flag (e.g. --script=evil), so validate strictly.
    err = _validate_host(target, allow_cidr=True)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["nmap"]
    if scan_type == "quick":
        cmd.extend(["-sS", "-T4"])
    elif scan_type == "service":
        cmd.extend(["-sV", "-T3"])
    elif scan_type == "full":
        cmd.extend(["-sV", "-sC", "-T3"])

    if ports == "top1000":
        cmd.append("--top-ports=1000")
    else:
        cmd.extend(["-p", ports])

    if scripts:
        cmd.extend(["--script", scripts])

    cmd.append(target)
    result = _run(cmd, timeout=300)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  WORKFLOW & ANALYSIS TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
def full_recon(domain: str) -> str:
    """
    Run a comprehensive recon pipeline on a domain.
    Performs: subdomain enum → HTTP probe → tech detection.
    Returns consolidated results.

    Args:
        domain: Target domain (e.g., "example.com")
    """
    err = _validate_host(domain)
    if err:
        return json.dumps(err, indent=2)
    results = {"domain": domain, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")}

    # Step 1: Subdomain enumeration
    print("[HYDRA] Step 1/3: Subdomain enumeration...", file=sys.stderr)
    sub_result = _run(["subfinder", "-d", domain, "-silent"], timeout=180)
    subdomains = []
    if sub_result["success"]:
        subdomains = [ln.strip() for ln in sub_result["output"].strip().split("\n")
                      if ln.strip()]
    results["subdomains"] = subdomains
    results["subdomain_count"] = len(subdomains)

    # Step 2: HTTP probe
    if subdomains:
        print("[HYDRA] Step 2/3: HTTP probing...", file=sys.stderr)
        probe_input = "\n".join(subdomains)
        probe_result = _run(["httpx", "-silent", "-sc", "-title"],
                           timeout=120, stdin_data=probe_input)
        live_hosts = []
        if probe_result["success"]:
            live_hosts = [ln.strip() for ln in probe_result["output"].strip().split("\n")
                         if ln.strip()]
        results["live_hosts"] = live_hosts
        results["live_count"] = len(live_hosts)
    else:
        results["live_hosts"] = []
        results["live_count"] = 0

    # Step 3: Tech detection on main domain
    print("[HYDRA] Step 3/3: Technology detection...", file=sys.stderr)
    url = f"https://{domain}"
    tech_result = _run(["whatweb", url, "--color=never"], timeout=60)
    results["technologies"] = tech_result.get("output", "")

    return json.dumps(results, indent=2)


@mcp.tool()
def check_tools() -> str:
    """
    Check which security tools are installed and available.
    Returns the availability status of each tool.
    """
    tools = {
        "subfinder": "Subdomain enumeration",
        "amass": "DNS enumeration",
        "httpx": "HTTP probing",
        "nuclei": "Vulnerability scanning",
        "ffuf": "Web fuzzing",
        "katana": "Web crawling",
        "gau": "URL gathering",
        "hakrawler": "Web crawling",
        "dnsx": "DNS resolution & enumeration",
        "whatweb": "Tech fingerprinting",
        "wafw00f": "WAF detection",
        "nmap": "Network scanning",
        "dirsearch": "Directory brute-forcing",
        "sqlmap": "SQL injection",
        "dalfox": "XSS scanning",
        "gxss": "XSS parameter reflection grep",
    }

    # Some binaries ship under alternate casing/names; check known aliases too.
    aliases = {
        "gxss": ["gxss", "Gxss"],
    }

    status = {}
    available = 0
    for tool, desc in tools.items():
        candidates = aliases.get(tool, [tool])
        path = next((shutil.which(c) for c in candidates if shutil.which(c)), None)
        status[tool] = {
            "available": path is not None,
            "path": path or "NOT FOUND",
            "description": desc,
        }
        if path:
            available += 1

    return json.dumps({
        "tools": status,
        "available": available,
        "total": len(tools),
        "summary": f"{available}/{len(tools)} tools installed",
    }, indent=2)


@mcp.tool()
def save_finding(title: str, severity: str, target: str,
                 description: str, evidence: str = "",
                 finding_type: str = "unknown") -> str:
    """
    Save a validated vulnerability finding to the HYDRA knowledge base
    for learning and future reference.

    Args:
        title: Short title of the finding
        severity: Severity level (critical, high, medium, low, info)
        target: Affected URL or host
        description: Detailed description of the vulnerability
        evidence: Proof/evidence of the vulnerability
        finding_type: Type of vulnerability (xss, sqli, ssrf, etc.)
    """
    conn = sqlite3.connect(str(LEARNING_DB))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT, severity TEXT, target TEXT,
            description TEXT, evidence TEXT, finding_type TEXT,
            created_at REAL
        )
    """)
    conn.execute(
        """INSERT INTO findings (title, severity, target, description,
           evidence, finding_type, created_at) VALUES (?,?,?,?,?,?,?)""",
        (title, severity, target, description, evidence, finding_type, time.time()),
    )
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    conn.close()

    return json.dumps({
        "saved": True, "title": title, "severity": severity,
        "total_findings_stored": count,
    }, indent=2)


@mcp.tool()
def get_findings(severity: str = "", limit: int = 50) -> str:
    """
    Retrieve saved vulnerability findings from the knowledge base.

    Args:
        severity: Filter by severity (empty = all)
        limit: Maximum number of findings to return
    """
    conn = sqlite3.connect(str(LEARNING_DB))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT, severity TEXT, target TEXT,
            description TEXT, evidence TEXT, finding_type TEXT,
            created_at REAL
        )
    """)

    if severity:
        rows = conn.execute(
            "SELECT * FROM findings WHERE severity = ? ORDER BY created_at DESC LIMIT ?",
            (severity, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY created_at DESC LIMIT ?", (limit,),
        ).fetchall()

    findings = [dict(r) for r in rows]
    conn.close()
    return json.dumps({"findings": findings, "count": len(findings)}, indent=2)


@mcp.tool()
def generate_report(target: str, findings_json: str,
                    report_format: str = "markdown") -> str:
    """
    Generate a structured bug bounty report from findings.

    Args:
        target: Target that was assessed
        findings_json: JSON string with array of findings
        report_format: "markdown" or "json"
    """
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid findings JSON"})

    scan_id = f"scan-{int(time.time())}"
    report_dir = REPORTS_DIR / scan_id
    report_dir.mkdir(parents=True, exist_ok=True)

    if report_format == "markdown":
        lines = [
            "# HYDRA Security Assessment Report",
            f"## Target: {target}",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Findings:** {len(findings)}",
            "",
        ]

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings,
            key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        for i, f in enumerate(sorted_findings, 1):
            lines.extend([
                f"### {i}. {f.get('title', f.get('name', 'Finding'))}",
                f"- **Severity:** {f.get('severity', 'unknown').upper()}",
                f"- **Host:** {f.get('host', f.get('matched_at', target))}",
                f"- **Type:** {f.get('type', f.get('template_id', 'N/A'))}",
                f"- **Description:** {f.get('description', 'N/A')}",
                "",
            ])

        report_content = "\n".join(lines)
        report_path = report_dir / "report.md"
        report_path.write_text(report_content, encoding="utf-8")
    else:
        report_content = json.dumps({
            "target": target, "scan_id": scan_id,
            "findings": findings, "count": len(findings),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }, indent=2)
        report_path = report_dir / "report.json"
        report_path.write_text(report_content, encoding="utf-8")

    return json.dumps({
        "report_path": str(report_path),
        "scan_id": scan_id,
        "format": report_format,
        "findings_count": len(findings),
    }, indent=2)


# ══════════════════════════════════════════════
#  TOOL 18 — sqlmap (SQL Injection)
# ══════════════════════════════════════════════

@mcp.tool()
def sqlmap_scan(
    target: str,
    level: int = 1,
    risk: int = 1,
    technique: str = "",
    tamper: str = "",
    batch: bool = True,
    timeout: int = 120,
) -> str:
    """
    Run sqlmap for automated SQL injection detection and exploitation.

    Args:
        target: Target URL with injectable parameter (e.g. http://example.com/page?id=1)
        level: Level of tests (1-5, higher = more tests, slower)
        risk: Risk of tests (1-3, higher = more aggressive)
        technique: Specific techniques: B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline
        tamper: Tamper scripts (e.g. "space2comment,between")
        batch: Non-interactive mode (auto-answer Yes to all)
        timeout: Execution timeout in seconds
    """
    err = _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["sqlmap", "-u", target, f"--level={level}", f"--risk={risk}",
           "--output-dir", str(RESULTS_DIR / "sqlmap")]
    if batch:
        cmd.append("--batch")
    if technique:
        cmd.extend(["--technique", technique])
    if tamper:
        cmd.extend(["--tamper", tamper])

    return json.dumps(_run(cmd, timeout=timeout), indent=2)


# ══════════════════════════════════════════════
#  TOOL 19 — dalfox (XSS Scanner)
# ══════════════════════════════════════════════

@mcp.tool()
def dalfox_scan(
    target: str,
    pipe_mode: bool = False,
    blind: str = "",
    timeout: int = 120,
) -> str:
    """
    Run dalfox for parameter analysis and XSS scanning.

    Args:
        target: Target URL for XSS testing
        pipe_mode: If true, target is treated as newline-delimited URLs via stdin
        blind: Blind XSS callback URL (your.xss.ht endpoint)
        timeout: Execution timeout in seconds
    """
    err = _validate_block(target, kind="any") if pipe_mode else _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    if pipe_mode:
        cmd = ["dalfox", "pipe", "--silence", "--format", "json"]
        result = _run(cmd, timeout=timeout, stdin_data=target)
    else:
        cmd = ["dalfox", "url", target, "--silence", "--format", "json"]
        if blind:
            cmd.extend(["--blind", blind])
        result = _run(cmd, timeout=timeout)

    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  TOOL 20 — gxss (XSS Parameter Grep)
# ══════════════════════════════════════════════

@mcp.tool()
def gxss_check(
    urls: str,
    timeout: int = 60,
) -> str:
    """
    Run gxss to check which URL parameters are reflected in response (XSS candidates).

    Args:
        urls: Newline-delimited URLs with parameters to check
        timeout: Execution timeout in seconds
    """
    err = _validate_block(urls, kind="url")
    if err:
        return json.dumps(err, indent=2)
    # Binary ships as "Gxss" (capital G) on Kali; some installs use "gxss".
    gxss_bin = shutil.which("gxss") or shutil.which("Gxss") or "Gxss"
    cmd = [gxss_bin]
    result = _run(cmd, timeout=timeout, stdin_data=urls)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  TOOL 21 — dnsx (DNS Resolution & Enumeration)
# ══════════════════════════════════════════════

@mcp.tool()
def dnsx_resolve(
    target: str,
    record_type: str = "A",
    wordlist: str = "",
    timeout: int = 60,
) -> str:
    """
    Run dnsx for fast DNS resolution and enumeration.

    Args:
        target: Domain or newline-delimited list of subdomains
        record_type: DNS record type: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, ANY
        wordlist: Optional wordlist for brute-force subdomain enumeration
        timeout: Execution timeout in seconds
    """
    # record_type is interpolated into a flag (f"-{record_type}") — constrain it
    # to a known DNS record-type allowlist so it cannot smuggle other options.
    if record_type.lower() not in _DNS_RECORD_TYPES:
        return json.dumps(_err(
            f"Rejected record_type '{record_type}': must be one of "
            f"{sorted(_DNS_RECORD_TYPES)}"), indent=2)
    block_err = _validate_host(target) if wordlist else _validate_block(target, kind="any")
    if block_err:
        return json.dumps(block_err, indent=2)
    cmd = ["dnsx", "-silent", f"-{record_type.lower()}", "-resp"]

    if wordlist:
        cmd.extend(["-w", wordlist, "-d", target])
        result = _run(cmd, timeout=timeout)
    else:
        # Pipe mode: feed subdomains via stdin
        cmd.append("-l")
        cmd.append("-")
        result = _run(cmd, timeout=timeout, stdin_data=target)

    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  TOOL 22 — hakrawler (Fast Web Crawler)
# ══════════════════════════════════════════════

@mcp.tool()
def hakrawler_crawl(
    target: str,
    depth: int = 2,
    scope: str = "subs",
    plain: bool = True,
    timeout: int = 90,
) -> str:
    """
    Run hakrawler for fast web crawling and endpoint discovery.

    Args:
        target: Target URL to crawl
        depth: Crawl depth (1-5)
        scope: Crawl scope: strict (same host), subs (include subdomains), fuzzy (all related)
        plain: Output plain URLs only
        timeout: Execution timeout in seconds
    """
    err = _validate_url(target)
    if err:
        return json.dumps(err, indent=2)
    cmd = ["hakrawler", "-url", target, "-depth", str(depth), "-scope", scope]
    if plain:
        cmd.append("-plain")

    result = _run(cmd, timeout=timeout)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
#  KNOWLEDGE OS TOOLS (Phase A — pure-python, no subprocess, offline-first)
#  These expose the hydra.knowledge / hydra.capabilities / hydra.recon_fusion
#  layer. Guarded import: the security tools above keep working even if the
#  knowledge layer is unavailable.
# ══════════════════════════════════════════════

try:
    from hydra.capabilities import CapabilityRegistry, ExecutionPolicy
    from hydra.knowledge.discovery import (
        ChainDiscovery,
        DiscoveryError,
        PatternDiscovery,
        confirm_candidate as _confirm_candidate,
    )
    from hydra.agents.planner import AgentIntelligence, AgentPlanner, AgentRouter
    from hydra.agents.registry import AgentRegistry
    from hydra.runtime.engine import RuntimeEngine, RuntimeIntelligence
    from hydra.runtime.workflows import WorkflowStateError, WorkflowStore
    from hydra.knowledge.governance import (
        DriftDetector,
        GovernanceIntelligence,
        KnowledgeQualityAnalyzer,
    )
    from hydra.adapters.adapter_registry import AdapterRegistry
    from hydra.adapters.intelligence import (
        AdapterIntelligence,
        CapabilityExerciseAnalyzer,
        RuntimeAnalytics,
    )
    from hydra.adapters.selection import AdapterSelector
    from hydra.intelligence.simulation import (
        AgentSimulation,
        CapabilityImpactAnalyzer,
        OutcomePredictor,
        PredictionAnalytics,
        SimulationContext,
        StrategyComparator,
        WorkflowOptimizationAdvisor,
        WorkflowSimulator,
    )
    from hydra.capabilities.dependency_graph import (
        CapabilityDependencyGraph,
        DependencyIntelligence,
    )
    from hydra.plugins.ecosystem import CapabilityMarketplace, EcosystemAnalyzer
    from hydra.plugins.health import PluginHealthAnalyzer
    from hydra.plugins.ownership import AgentOwnershipResolver
    from hydra.plugins.plugin_catalog import EffectiveCapabilityCatalog
    from hydra.plugins.plugin_registry import PluginRegistry as _PluginRegistry
    from hydra.federation.consensus import ConsensusEngine as _ConsensusEngine
    from hydra.federation.digest import KnowledgeDigestGenerator as _DigestGenerator
    from hydra.federation.intelligence import IntelligenceMesh as _IntelligenceMesh
    from hydra.federation.marketplace import FederationMarketplace as _FederationMarketplace
    from hydra.federation.registry import FederationRegistry as _FederationRegistry
    from hydra.federation.safety import FederationSafetyError as _FederationSafetyError
    from hydra.federation.store import KnowledgeExchangeStore as _ExchangeStore
    from hydra.temporal_intel.context import TemporalContext as _TemporalContext
    from hydra.temporal_intel.forecast import TemporalForecastEngine as _TemporalForecast
    from hydra.temporal_intel.intelligence import TemporalIntelligence as _TemporalIntelligence
    from hydra.temporal_intel.trends import MomentumAnalyzer as _MomentumAnalyzer
    from hydra.temporal_intel.trends import TrendAnalyzer as _TrendAnalyzer
    from hydra.capabilities.capability_catalog import CapabilityCatalog
    from hydra.capabilities.source_learning import SourceLearningStore
    from hydra.capabilities.source_selection import AdaptiveSourceSelector
    from hydra.capabilities.tool_capabilities import ToolCapabilityRegistry
    from hydra.capabilities.tool_selection import CapabilityCoverage, ToolSelector
    from hydra.knowledge.verification import (
        ValidationIntelligence,
        VerificationLearningStore,
        VerificationPlaybookGenerator,
    )
    from hydra.recon_fusion.recon_planner import ReconPlanner
    from hydra.knowledge.graph_index import KnowledgeGraphIndex
    from hydra.knowledge.graph_index import rebuild as _kb_rebuild
    from hydra.knowledge.memory import OffensiveMemory
    from hydra.knowledge.opportunity import (
        OpportunityScorer,
        record_fusion_discoveries as _record_fusion_discoveries,
    )
    from hydra.knowledge.opportunity import record_outcome as _record_outcome
    from hydra.knowledge.promotion import PromotionError, apply_promotion
    from hydra.knowledge.report_intel import ReportIntelligencePipeline, ReportSource
    from hydra.knowledge.schema import NodeType as _NodeType
    from hydra.knowledge.schema import Stage as _Stage
    from hydra.knowledge.wiki_store import WikiStore
    from hydra.recon_fusion import ReconFusionPipeline
    _KB_OK = True
except Exception as _kb_err:  # pragma: no cover - knowledge layer optional
    _KB_OK = False
    _KB_IMPORT_ERROR = str(_kb_err)


def _kb_guard():
    if not _KB_OK:
        return json.dumps({"success": False, "error": f"knowledge layer unavailable: {_KB_IMPORT_ERROR}"})
    return None


@mcp.tool()
def capability_list() -> str:
    """List declared reconnaissance capabilities and their outputs (capability-first model)."""
    if (g := _kb_guard()):
        return g
    reg = CapabilityRegistry().load()
    caps = []
    for name in reg.names():
        c = reg.get(name)
        caps.append({"capability": name, "outputs": c.outputs,
                     "source_count": len(c.sources), "description": c.description})
    return json.dumps({"capabilities": caps, "count": len(caps)}, indent=2)


@mcp.tool()
def capability_sources(capability: str, online: bool = False) -> str:
    """List a capability's sources with metadata and whether each is runnable under the current policy.

    Args:
        capability: capability name (e.g. "discover_subdomains")
        online: if True, evaluate runnability under online policy (keys from HYDRA_SOURCE_KEYS)
    """
    if (g := _kb_guard()):
        return g
    reg = CapabilityRegistry().load()
    cap = reg.get(capability)
    if not cap:
        return json.dumps({"success": False, "error": f"unknown capability: {capability}"})
    policy = _policy(online)
    sources = [{**s.to_dict(), "runnable": s.runnable(policy)} for s in cap.sources]
    return json.dumps({"capability": capability, "policy": policy.mode,
                       "sources": sources, "count": len(sources)}, indent=2)


@mcp.tool()
def recon_fuse(domain: str, capability: str = "discover_subdomains", online: bool = False) -> str:
    """Run the recon knowledge-fusion pipeline (offline-first) and write Asset Intelligence to the wiki.

    Collects from policy-allowed sources, normalizes/dedups, scores confidence by the
    Two-Signal rule, writes canonical wiki asset pages (with backlinks), rebuilds the
    graph index, and attaches prior knowledge from Offensive Memory.

    Args:
        domain: target domain (validated; raw tool output never becomes knowledge directly)
        capability: which capability to fuse (default discover_subdomains)
        online: enable network sources (requires keys; Phase E adapters)
    """
    if (g := _kb_guard()):
        return g
    err = _validate_host(domain)
    if err:
        return json.dumps(err, indent=2)
    try:
        result = ReconFusionPipeline().run(domain, capability, _policy(online), materialize=True)
    except KeyError as e:
        return json.dumps({"success": False, "error": str(e)})
    # Phase D: credit contributing sources (discovery side of effectiveness). Derived
    # learning store only — never the wiki; best-effort so fusion never fails on it.
    try:
        _record_fusion_discoveries(result)
    except Exception:
        pass
    priors = [h.to_dict() for h in OffensiveMemory().recall(domain, target=domain, limit=5)]
    return json.dumps({
        "success": True,
        **result.summary(),
        "assets": [a.to_dict() for a in result.assets],
        "materialized_pages": result.materialized,
        "prior_knowledge": priors,
    }, indent=2)


@mcp.tool()
def kb_recall(query: str, types: str = "", target: str = "", limit: int = 10) -> str:
    """Offensive Memory: search-first recall of prior knowledge before planning.

    Args:
        query: free-text query (e.g. "waf bypass cors")
        types: optional comma-separated node types to restrict (technique,pattern,chain,finding,intel,hypothesis)
        target: optional target slug to boost graph-near pages
        limit: max hits
    """
    if (g := _kb_guard()):
        return g
    type_list = None
    if types.strip():
        type_list = []
        for t in types.split(","):
            try:
                type_list.append(_NodeType.from_str(t.strip()))
            except ValueError:
                pass
    hits = OffensiveMemory().recall(query, types=type_list, target=target or None, limit=limit)
    return json.dumps({"query": query, "hits": [h.to_dict() for h in hits], "count": len(hits)}, indent=2)


@mcp.tool()
def kb_lint() -> str:
    """Wiki/graph health check: orphan pages, dangling links, and type breakdown."""
    if (g := _kb_guard()):
        return g
    idx = KnowledgeGraphIndex.build(WikiStore())
    return json.dumps({
        "stats": idx.stats(),
        "orphans": idx.orphans(),
        "dangling_links": [{"from": s, "missing": d} for s, d in idx.dangling_links()],
    }, indent=2)


@mcp.tool()
def kb_promote(page: str, to_stage: str, evidence_count: int = 0, sources: str = "",
               scope_ok: bool = True) -> str:
    """Promote a wiki page up the knowledge hierarchy with hard guardrails.

    Forbidden transitions (e.g. hypothesis→pattern, hypothesis→chain) and missing
    evidence / Two-Signal violations are rejected.

    Args:
        page: page slug
        to_stage: target stage (intel|hypothesis|finding|pattern|chain)
        evidence_count: number of supporting evidence items
        sources: optional comma-separated independent source ids
        scope_ok: whether the target is in scope (required to reach 'finding')
    """
    if (g := _kb_guard()):
        return g
    store = WikiStore()
    wp = store.get(page)
    if wp is None:
        return json.dumps({"success": False, "error": f"page not found: {page}"})
    try:
        stage = _Stage(to_stage.strip().lower())
    except ValueError:
        return json.dumps({"success": False, "error": f"invalid stage: {to_stage}"})
    src_list = [s.strip() for s in sources.split(",") if s.strip()]
    try:
        apply_promotion(wp, stage, sources=src_list, evidence_count=evidence_count, scope_ok=scope_ok)
    except PromotionError as e:
        return json.dumps({"success": False, "rejected": True, "reason": str(e)})
    store.write_page(wp)
    return json.dumps({"success": True, "page": page, "promoted_to": stage.value})


@mcp.tool()
def kb_rebuild_index() -> str:
    """Rebuild the derived graph index from the canonical wiki (the index is disposable)."""
    if (g := _kb_guard()):
        return g
    return json.dumps({"success": True, "stats": _kb_rebuild(WikiStore())}, indent=2)


@mcp.tool()
def asset_lookup(asset: str) -> str:
    """Look up a discovered asset's intelligence (confidence, sources, related links) from the wiki."""
    if (g := _kb_guard()):
        return g
    store = WikiStore()
    page = store.get(asset, _NodeType.ASSET)
    if page is None:
        return json.dumps({"success": False, "error": f"no asset page for: {asset}"})
    return json.dumps({
        "success": True, "asset": asset, "path": str(page.path),
        "confidence": page.meta.get("confidence"), "sources": page.meta.get("sources", []),
        "scope_status": page.meta.get("scope_status"),
        "related": [s for s in page.links],
    }, indent=2)


@mcp.tool()
def graph_neighbors(page: str) -> str:
    """Return the knowledge-graph neighbors (inbound + outbound links) of a wiki page."""
    if (g := _kb_guard()):
        return g
    idx = KnowledgeGraphIndex.build(WikiStore())
    if page not in idx.nodes:
        return json.dumps({"success": False, "error": f"page not in graph: {page}"})
    return json.dumps({
        "page": page, "type": idx.nodes.get(page),
        "neighbors": idx.neighbors(page),
        "related_findings": idx.related_findings(page),
        "related_patterns": idx.related_patterns(page),
        "related_chains": idx.related_chains(page),
    }, indent=2)


@mcp.tool()
def graph_path(source_page: str, target_page: str) -> str:
    """Return the shortest path between two knowledge-graph nodes (offensive leverage discovery)."""
    if (g := _kb_guard()):
        return g
    idx = KnowledgeGraphIndex.build(WikiStore())
    path = idx.shortest_path(source_page, target_page)
    return json.dumps({"from": source_page, "to": target_page,
                       "path": path, "length": max(0, len(path) - 1), "reachable": bool(path)}, indent=2)


@mcp.tool()
def discover_patterns(min_support: int = 2) -> str:
    """Propose recurring-pattern candidates across the wiki (Phase C — DRY-RUN, creates nothing).

    Synthesizes patterns from ≥2 independent weighted evidence sources (validated
    findings + report-intel; hypotheses excluded). Returns ranked candidates with a
    machine-readable `explain` block and a create_new/strengthen_existing recommendation.
    Nothing is written — materialize with `confirm_candidate`.

    Args:
        min_support: minimum independent evidence sources required (>=2).
    """
    if (g := _kb_guard()):
        return g
    cands = PatternDiscovery(WikiStore()).discover(min_support=max(2, min_support))
    return json.dumps({"candidate_type": "pattern", "count": len(cands),
                       "candidates": [c.to_dict() for c in cands]}, indent=2)


@mcp.tool()
def discover_chains(min_support: int = 2) -> str:
    """Propose multi-step chain candidates (Phase C — DRY-RUN, creates nothing).

    Conservative: chains are formed only from a shared target, a shared asset, or an
    explicit graph path between validated findings — never from semantic similarity.
    Returns ranked candidates; materialize with `confirm_candidate`.

    Args:
        min_support: minimum validated-finding steps required (>=2).
    """
    if (g := _kb_guard()):
        return g
    cands = ChainDiscovery(WikiStore()).discover(min_support=max(2, min_support))
    return json.dumps({"candidate_type": "chain", "count": len(cands),
                       "candidates": [c.to_dict() for c in cands]}, indent=2)


@mcp.tool()
def confirm_candidate(candidate_type: str, candidate_id: str) -> str:
    """Explicitly materialize a discovered candidate into a canonical pattern/chain page.

    The only Phase-C write path. Concurrency-safe: re-runs discovery, re-validates the
    candidate by id and the two-signal gate, existence-checks before writing, and on a
    strengthen_existing recommendation merges into the single canonical page. Idempotent.

    Args:
        candidate_type: "pattern" or "chain".
        candidate_id: the id returned by discover_patterns / discover_chains.
    """
    if (g := _kb_guard()):
        return g
    try:
        result = _confirm_candidate(candidate_type, candidate_id, WikiStore())
    except DiscoveryError as e:
        return json.dumps({"success": False, "rejected": True, "reason": str(e)})
    return json.dumps({"success": True, **result}, indent=2)


# ── Phase D — Source Performance Learning & Opportunity Ranking ──────────────────

@mcp.tool()
def record_outcome(candidate_type: str, candidate_id: str, outcome: str) -> str:
    """Record verification feedback for a candidate (Phase D — learning only).

    `outcome` = "confirmed" or "rejected". Attributes the result to the candidate's
    contributing recon sources and appends events to the DERIVED source-learning store.
    Affects source-performance learning ONLY — it never alters promotion rules,
    confidence, or any canonical wiki content.

    Args:
        candidate_type: "pattern" or "chain".
        candidate_id: id from discover_patterns / discover_chains.
        outcome: "confirmed" or "rejected".
    """
    if (g := _kb_guard()):
        return g
    try:
        res = _record_outcome(candidate_type, candidate_id, outcome, WikiStore())
    except ValueError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"success": True, **res}, indent=2)


@mcp.tool()
def source_scores(source_id: str = "") -> str:
    """Read derived per-source learning scores (trust / novelty / effectiveness).

    Rebuildable from the raw event log; never canonical. Pass a `source_id` for one
    source, or omit for all sources with recorded history.
    """
    if (g := _kb_guard()):
        return g
    learn = SourceLearningStore()
    if source_id:
        return json.dumps({"source": source_id, "scores": learn.scores(source_id).to_dict()}, indent=2)
    return json.dumps({"sources": [s.to_dict() for s in learn.all_scores()]}, indent=2)


@mcp.tool()
def rank_opportunities(limit: int = 20) -> str:
    """Rank current discovery candidates as investigation opportunities (Phase D).

    Non-canonical OpportunityScore = weighted blend of the candidate's (already-assigned)
    confidence band, contributing-source effectiveness/novelty, chain potential and
    evidence diversity. Read-only; deterministic; confidence.py is never modified.
    """
    if (g := _kb_guard()):
        return g
    ranked = OpportunityScorer(WikiStore()).rank(limit=max(1, limit))
    return json.dumps({"count": len(ranked), "opportunities": [o.to_dict() for o in ranked]}, indent=2)


@mcp.tool()
def prioritization_report() -> str:
    """Knowledge-guided prioritization (Phase D, read-only) — powers future Adaptive Recon.

    Answers: which pattern signatures historically succeed, which source CATEGORIES
    generate confirmed findings, and which evidence-class combinations get accepted.
    All derived from the learning event log; nothing canonical is read or written.
    """
    if (g := _kb_guard()):
        return g
    learn = SourceLearningStore()
    # source.id → category, from the capability registry (kept out of the store).
    reg = CapabilityRegistry().load()
    category_of = {}
    for name in reg.names():
        for s in reg.get(name).sources:
            category_of.setdefault(s.id, s.category.value)
    return json.dumps({
        "successful_patterns": learn.successful_patterns(),
        "effective_source_types": learn.effective_source_types(category_of),
        "accepted_evidence_combos": learn.accepted_evidence_combos(),
    }, indent=2)


# ── Phase E — Adaptive Recon & Autonomous Source Selection (advisory) ────────────

@mcp.tool()
def select_sources(capability: str, online: bool = False, limit: int = 10) -> str:
    """Rank a capability's recon sources using accumulated learning (Phase E — advisory).

    Blends trust / effectiveness (recency-decayed) / novelty / exploration / declared
    prior into a deterministic ranking. Read-only over the derived learning store;
    never modifies confidence, promotion, or the wiki. `runnable` reflects the current
    offline/online policy.

    Args:
        capability: e.g. "discover_subdomains".
        online: evaluate runnability under online policy (keys from HYDRA_SOURCE_KEYS).
        limit: max sources to return.
    """
    if (g := _kb_guard()):
        return g
    try:
        ranked = AdaptiveSourceSelector().select(capability, _policy(online), limit=max(1, limit))
    except KeyError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"success": True, "capability": capability,
                       "sources": [s.to_dict() for s in ranked]}, indent=2)


@mcp.tool()
def recon_plan(target: str, target_type: str = "web", prior_findings: int = 0,
               online: bool = False) -> str:
    """Produce an advisory, learning-driven reconnaissance plan (Phase E).

    Returns an ordered capability plan with learning-ranked sources, an expected-value
    estimate, and opportunity-driven emphasis. ADVISORY ONLY — it recommends; it never
    executes recon, confirms findings, writes the wiki, or alters confidence/promotion.

    Args:
        target: target host/domain.
        target_type: web | api | cloud | network | code (selects relevant capabilities).
        prior_findings: count of existing findings for the target (caller-supplied; keeps planning O(1)).
        online: plan against online-runnable sources too.
    """
    if (g := _kb_guard()):
        return g
    err = _validate_host(target)
    if err:
        return json.dumps(err, indent=2)
    plan = ReconPlanner().plan(target, target_type=target_type,
                               prior_findings=max(0, prior_findings), exec_policy=_policy(online))
    return json.dumps({"success": True, **plan.to_dict()}, indent=2)


# ── Phase F — Verification Learning & Validation Intelligence (advisory) ─────────

@mcp.tool()
def record_verification(vuln_class: str, method: str, outcome: str,
                        evidence_type: str = "", evidence_strength: float = 0.0,
                        source_ids: str = "", dedup_key: str = "") -> str:
    """Record how a finding was verified (Phase F — learning only).

    `outcome` = "success" or "failure". Appends to the DERIVED verification-learning
    store. A non-empty `dedup_key` makes the record idempotent. Learning only — never
    confirms a finding, executes a verification, writes the wiki, or alters confidence.

    Args:
        vuln_class: vulnerability class (e.g. "idor").
        method: verification method/tool (e.g. "idor_verifier").
        outcome: "success" | "failure".
        evidence_type: type of evidence used (e.g. "auth_swap_response").
        evidence_strength: 0..1 strength of the evidence.
        source_ids: comma-separated contributing recon source.ids.
        dedup_key: optional idempotency key.
    """
    if (g := _kb_guard()):
        return g
    sids = [s.strip() for s in source_ids.split(",") if s.strip()]
    try:
        newly = VerificationLearningStore().record_verification(
            vuln_class, method, outcome, evidence_type=evidence_type,
            evidence_strength=evidence_strength, source_ids=sids,
            dedup_key=dedup_key or None)
    except ValueError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"success": True, "recorded": bool(newly), "idempotent_skip": not newly,
                       "vuln_class": vuln_class, "method": method, "outcome": outcome}, indent=2)


@mcp.tool()
def verification_stats() -> str:
    """Validation intelligence (Phase F, read-only): how findings get verified.

    Returns per-method / per-vuln-class / per-evidence-type / per-source-category
    success statistics, derived deterministically from the verification event log.
    """
    if (g := _kb_guard()):
        return g
    reg = CapabilityRegistry().load()
    category_of = {}
    for name in reg.names():
        for s in reg.get(name).sources:
            category_of.setdefault(s.id, s.category.value)
    return json.dumps(ValidationIntelligence().summary(category_of), indent=2)


@mcp.tool()
def verification_playbook(vuln_class: str) -> str:
    """Generate an advisory verification playbook for a vulnerability class (Phase F).

    Ranked verification steps (learned methods merged with a static default catalog),
    an expected-verification-value and a confidence-of-success. ADVISORY — it never
    executes a verification or confirms a finding.
    """
    if (g := _kb_guard()):
        return g
    pb = VerificationPlaybookGenerator().generate(vuln_class)
    return json.dumps({"success": True, **pb.to_dict()}, indent=2)


@mcp.tool()
def tool_capabilities(category: str = "") -> str:
    """List the modelled tool-capability catalog (Phase F) — recon/web/cloud/verification.

    Capability modeling for future tool expansion (no integrations). Verification tools
    include their historical effectiveness, read from the derived verification store.

    Args:
        category: optional filter (recon | web | cloud | verification).
    """
    if (g := _kb_guard()):
        return g
    reg = ToolCapabilityRegistry().load()
    vstore = VerificationLearningStore()
    tools = reg.by_category(category) if category else reg.all()
    out = []
    for t in tools:
        eff = reg.effectiveness(t.id, vstore) if t.is_verifier else None
        out.append(t.to_dict(effectiveness=eff))
    return json.dumps({"count": len(out), "categories": reg.categories(), "tools": out}, indent=2)


# ── Phase G — Capability Expansion & Tool Orchestration (read-only) ──────────────

@mcp.tool()
def capability_catalog(category: str = "") -> str:
    """List the capability-centric orchestration catalog v2 (Phase G, read-only).

    Each entry is a CAPABILITY (mapping to interchangeable tools) with its category,
    supported target/finding types, verification coverage, offline-runnable flag and
    confidence weight. Capability modeling only — no integrations/execution.

    Args:
        category: optional filter (reconnaissance|web|api|cloud|source_code|secrets|mobile|infrastructure|verification).
    """
    if (g := _kb_guard()):
        return g
    cat = CapabilityCatalog().load()
    entries = cat.by_category(category) if category else cat.all()
    return json.dumps({
        "count": len(entries), "total_capabilities": cat.count(),
        "categories": cat.categories(), "category_counts": cat.category_counts(),
        "distinct_tools": len(cat.all_tools()),
        "capabilities": [e.to_dict() for e in entries],
    }, indent=2)


@mcp.tool()
def capability_coverage() -> str:
    """Capability coverage intelligence (Phase G, read-only).

    Reports uncovered capabilities, weakest capability areas, over-used tools and
    under-explored tools — derived from the catalog + learning stores. Advisory.
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(CapabilityCoverage().report(), indent=2)


@mcp.tool()
def rank_tools(capability: str, limit: int = 10) -> str:
    """Rank a capability's interchangeable tools by accumulated learning (Phase G, read-only).

    Blends recon effectiveness (recency-decayed) + verification effectiveness +
    exploration + trust + the capability's prior. Deterministic given the current time.
    """
    if (g := _kb_guard()):
        return g
    try:
        ranked = ToolSelector().rank(capability, limit=max(1, limit))
    except KeyError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"success": True, "capability": capability,
                       "tools": [t.to_dict() for t in ranked]}, indent=2)


@mcp.tool()
def select_tool(capability: str) -> str:
    """Select the single best-ranked tool for a capability (Phase G, read-only, advisory)."""
    if (g := _kb_guard()):
        return g
    try:
        best = ToolSelector().select(capability)
    except KeyError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"success": True, "capability": capability,
                       "tool": best.to_dict() if best else None}, indent=2)


# ── Phase H — Multi-Agent Orchestration Layer (read-only, advisory) ──────────────

@mcp.tool()
def agent_catalog() -> str:
    """List the specialized agent definitions (Phase H, read-only).

    Each agent declares responsibilities, allowed capability categories, priority and
    expected outputs. Agents orchestrate the capability layer — they never execute
    tools, confirm findings, or write the wiki.
    """
    if (g := _kb_guard()):
        return g
    reg = AgentRegistry().load()
    return json.dumps({"agent_count": reg.count(),
                       "agents": [a.to_dict() for a in reg.all()]}, indent=2)


@mcp.tool()
def agent_plan(target: str, target_type: str = "web", prior_findings: int = 0) -> str:
    """Produce an advisory, priority-ordered multi-agent workflow for a target (Phase H).

    Returns the ordered agents, the capabilities assigned to each, an expected-value
    estimate and reasoning. ADVISORY — it plans; it never executes or confirms.

    Args:
        target: target host/domain.
        target_type: web | api | cloud | network | code | mobile.
        prior_findings: count of existing findings (caller-supplied; keeps planning O(1)).
    """
    if (g := _kb_guard()):
        return g
    err = _validate_host(target)
    if err:
        return json.dumps(err, indent=2)
    plan = AgentPlanner().plan(target, target_type=target_type, prior_findings=max(0, prior_findings))
    return json.dumps({"success": True, **plan.to_dict()}, indent=2)


@mcp.tool()
def agent_route(target: str, target_type: str = "web") -> str:
    """Deterministic Target → Agent → Capability → Tool routing (Phase H, read-only).

    Shows, per applicable agent, the capabilities it owns for this target and the
    learning-selected best tool for each. Advisory; nothing is executed.
    """
    if (g := _kb_guard()):
        return g
    err = _validate_host(target)
    if err:
        return json.dumps(err, indent=2)
    return json.dumps({"success": True, **AgentRouter().route(target, target_type=target_type)}, indent=2)


@mcp.tool()
def agent_coverage() -> str:
    """Agent orchestration intelligence (Phase H, read-only).

    Agent effectiveness, capability ownership (orphans/overlaps), workflow coverage,
    bottlenecks and under-utilized agents — derived from the catalog + learning stores.
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(AgentIntelligence().report(), indent=2)


# ── Phase I — Execution Runtime & Workflow Engine (state only; no execution) ─────

@mcp.tool()
def workflow_create(target: str, target_type: str = "web", prior_findings: int = 0) -> str:
    """Create a deterministic PENDING workflow from the agent plan (Phase I).

    Builds the agent→capability→tool plan and persists it as a workflow + tasks in the
    DERIVED runtime store (data/workflows.db). Idempotent (deterministic workflow_id).
    Executes NOTHING — it only records workflow state. Never writes the wiki, confirms
    findings, or runs tools.

    Args:
        target: target host/domain.
        target_type: web | api | cloud | network | code | mobile.
        prior_findings: count of existing findings (caller-supplied; keeps planning O(1)).
    """
    if (g := _kb_guard()):
        return g
    err = _validate_host(target)
    if err:
        return json.dumps(err, indent=2)
    eng = RuntimeEngine()
    wf_id = eng.create_workflow(target, target_type=target_type, prior_findings=max(0, prior_findings))
    st = eng.workflow_status(wf_id)
    return json.dumps({"success": True, "workflow_id": wf_id,
                       "status": st["workflow"]["status"], "task_count": len(st["tasks"])}, indent=2)


@mcp.tool()
def workflow_status(workflow_id: str) -> str:
    """Read a workflow's current state and its task states (Phase I, read-only)."""
    if (g := _kb_guard()):
        return g
    try:
        return json.dumps({"success": True, **RuntimeEngine().workflow_status(workflow_id)}, indent=2)
    except WorkflowStateError as e:
        return json.dumps({"success": False, "error": str(e)})


@mcp.tool()
def workflow_history(workflow_id: str = "") -> str:
    """List workflows, or one workflow's task history (Phase I, read-only)."""
    if (g := _kb_guard()):
        return g
    store = WorkflowStore()
    if workflow_id:
        wf = store.get_workflow(workflow_id)
        if wf is None:
            return json.dumps({"success": False, "error": f"unknown workflow: {workflow_id}"})
        return json.dumps({"success": True, "workflow": wf, "tasks": store.get_tasks(workflow_id)}, indent=2)
    return json.dumps({"success": True, "workflows": store.list_workflows()}, indent=2)


@mcp.tool()
def runtime_summary() -> str:
    """Runtime intelligence (Phase I, read-only): workflow/agent/failure/retry/coverage stats."""
    if (g := _kb_guard()):
        return g
    return json.dumps(RuntimeIntelligence().report(), indent=2)


# ── Phase J — Knowledge Governance, Drift Detection & QA (read-only, advisory) ───

@mcp.tool()
def governance_summary() -> str:
    """Knowledge governance summary (Phase J, read-only, advisory).

    Knowledge health score (0-100) + components, drift counts, weakest/healthiest
    areas, graph health, and advisory lifecycle recommendations. Derived from the
    canonical wiki + learning stores; writes nothing and never alters
    confidence/promotion.
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(GovernanceIntelligence().governance_summary(), indent=2)


@mcp.tool()
def drift_report() -> str:
    """Knowledge drift report (Phase J, read-only): stale patterns/chains/findings/sources,
    declining source/verification effectiveness, and capability drift — each with
    severity, confidence, rationale and a suggested (advisory) action."""
    if (g := _kb_guard()):
        return g
    return json.dumps(DriftDetector().report(), indent=2)


@mcp.tool()
def knowledge_health() -> str:
    """Deterministic knowledge health score 0-100 with quality metrics (Phase J, read-only)."""
    if (g := _kb_guard()):
        return g
    qa = KnowledgeQualityAnalyzer()
    health = qa.health_score()
    metrics = qa.metrics()
    return json.dumps({
        "score": health.score, "components": health.components,
        "metrics": {k: v for k, v in metrics.items()
                    if k not in ("duplicate_groups", "contradictions")},
    }, indent=2)


@mcp.tool()
def stale_entities() -> str:
    """List stale knowledge entities (patterns/chains/findings/sources) — advisory (Phase J)."""
    if (g := _kb_guard()):
        return g
    return json.dumps({"stale_entities": GovernanceIntelligence().stale_entities()}, indent=2)


@mcp.tool()
def duplicate_patterns() -> str:
    """Report candidate duplicate patterns (same derived signature) for review (Phase J, read-only)."""
    if (g := _kb_guard()):
        return g
    groups = GovernanceIntelligence().duplicate_patterns()
    return json.dumps({"duplicate_groups": groups, "group_count": len(groups)}, indent=2)


@mcp.tool()
def contradiction_report() -> str:
    """Report contradiction candidates — hosts with both validated and rejected findings (Phase J)."""
    if (g := _kb_guard()):
        return g
    contradictions = GovernanceIntelligence().contradiction_report()
    return json.dumps({"contradictions": contradictions, "count": len(contradictions)}, indent=2)


# ── Phase K — Adapter Framework & Sandboxed Tool Integrations (read-only, advisory) ──

@mcp.tool()
def adapter_catalog(capability: str = "", category: str = "") -> str:
    """List synthesized adapter definitions (Phase K, read-only, no execution).

    Adapters are derived deterministically from the capability catalog (one per
    capability×tool). Each carries an execution_profile (safe profiles only),
    timeouts, I/O schemas, and offline/validation/simulation support flags.

    Args:
        capability: optional — only adapters for this capability_id
        category:   optional — only adapters in this category
    """
    if (g := _kb_guard()):
        return g
    reg = AdapterRegistry().load()
    if capability:
        adapters = reg.adapters_for_capability(capability)
    elif category:
        adapters = reg.adapters_for_category(category)
    else:
        adapters = reg.all_adapters()
    return json.dumps({"count": len(adapters), "supported_profiles": reg.supported_profiles(),
                       "adapters": [a.to_dict() for a in adapters]}, indent=2)


@mcp.tool()
def adapter_coverage() -> str:
    """Adapter + capability-exercise coverage (Phase K, read-only).

    Reports adapter coverage over the capability catalog (by category/profile) plus
    capability EXERCISE metrics (declared/owned/has-adapter/exercised/verified) — the
    governance blind spot identified in Phase J."""
    if (g := _kb_guard()):
        return g
    reg = AdapterRegistry().load()
    exercise = CapabilityExerciseAnalyzer(registry=reg).report().to_dict()
    return json.dumps({"adapter_coverage": reg.adapter_coverage(),
                       "capability_exercise": exercise}, indent=2)


@mcp.tool()
def adapter_health(adapter_id: str = "") -> str:
    """Adapter tool-health metrics (Phase K, read-only, derived/rebuildable).

    With an adapter_id: that adapter's health. Without: healthiest + weakest adapters,
    failures and timeouts. Metrics (reliability/runtime/success/failure/timeout) are
    pure functions of the event log under data/tool_health.db.

    Args:
        adapter_id: optional — "<capability_id>::<tool>" (e.g. "port_scanning::nmap")
    """
    if (g := _kb_guard()):
        return g
    from hydra.adapters.tool_health import ToolHealthStore
    if adapter_id:
        return json.dumps(ToolHealthStore().health(adapter_id).to_dict(), indent=2)
    ai = AdapterIntelligence(AdapterRegistry().load())
    return json.dumps({
        "healthiest": ai.healthiest_adapters(), "weakest": ai.weakest_adapters(),
        "failures": ai.adapter_failures(), "timeouts": ai.adapter_timeouts(),
    }, indent=2)


@mcp.tool()
def adapter_summary() -> str:
    """Adapter ecosystem summary (Phase K, read-only): totals, utilization, mean
    reliability, and execution/validation/simulation/success/failure/timeout counts."""
    if (g := _kb_guard()):
        return g
    return json.dumps(AdapterIntelligence(AdapterRegistry().load()).adapter_summary(), indent=2)


@mcp.tool()
def adapter_select(capability: str, limit: int = 5) -> str:
    """Rank a capability's adapters by learning (Phase K, advisory, no execution).

    Combines source-learning effectiveness (recency-decayed), tool-health reliability,
    verification success, trust, an anti-monopoly exploration bonus, and the capability
    prior. Deterministic; ADVISORY — selects, never executes.

    Args:
        capability: capability_id whose adapters to rank
        limit: max adapters to return (default 5)
    """
    if (g := _kb_guard()):
        return g
    try:
        ranked = AdapterSelector(AdapterRegistry().load()).rank(capability, limit=max(1, limit))
    except KeyError as e:
        return json.dumps({"success": False, "error": str(e)})
    return json.dumps({"capability": capability, "count": len(ranked),
                       "ranked_adapters": [s.to_dict() for s in ranked]}, indent=2)


@mcp.tool()
def runtime_analytics() -> str:
    """Adapter runtime analytics (Phase K, read-only): utilization, average runtime,
    timeout distribution, per-category coverage, and execution-profile distribution."""
    if (g := _kb_guard()):
        return g
    return json.dumps(RuntimeAnalytics(AdapterRegistry().load()).report(), indent=2)


# ── Phase L — Autonomous Knowledge Simulation & Decision Intelligence (read-only) ────

@mcp.tool()
def simulate_workflow(workflow_id: str = "", target: str = "", target_type: str = "web") -> str:
    """Simulate a workflow/agent-plan outcome BEFORE execution (Phase L, advisory, no execution).

    Predicts expected findings, verification success, evidence/source diversity, chain &
    pattern generation, and completion probability — purely from historical learning stores.

    Args:
        workflow_id: simulate an existing runtime workflow's capability plan
        target: alternatively, simulate the agent plan for this target
        target_type: web|api|cloud|mobile|network|code (default web)
    """
    if (g := _kb_guard()):
        return g
    sim = WorkflowSimulator(SimulationContext())
    return json.dumps(sim.simulate(workflow_id=workflow_id, target=target,
                                   target_type=target_type).to_dict(), indent=2)


@mcp.tool()
def simulate_strategy(target_type: str = "web") -> str:
    """Compare recon strategies (aggressive/balanced/verification-first) by predicted score,
    confidence, rationale and tradeoffs (Phase L, advisory, simulation only).

    Args:
        target_type: web|api|cloud|mobile|network|code (default web)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(StrategyComparator(SimulationContext()).compare(target_type), indent=2)


@mcp.tool()
def predict_outcome(workflow_id: str = "", target: str = "", target_type: str = "web") -> str:
    """Forecast outcome probabilities (Phase L, read-only): success, stale results, new
    patterns, new chains, source bias — from historical events.

    Args:
        workflow_id: an existing runtime workflow
        target: alternatively, the agent plan for this target
        target_type: web|api|cloud|mobile|network|code
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(OutcomePredictor(SimulationContext()).predict(
        workflow_id=workflow_id, target=target, target_type=target_type), indent=2)


@mcp.tool()
def capability_impact(capability: str = "") -> str:
    """Per-capability impact estimate (Phase L, read-only): expected value/findings/
    verification rate/chain & pattern contribution from learning + adapter health.

    Args:
        capability: a capability_id; omit for all capabilities (ranked by expected value)
    """
    if (g := _kb_guard()):
        return g
    an = CapabilityImpactAnalyzer(SimulationContext())
    if capability:
        try:
            return json.dumps(an.impact(capability).to_dict(), indent=2)
        except KeyError as e:
            return json.dumps({"success": False, "error": str(e)})
    impacts = sorted((i.to_dict() for i in an.all_impacts()),
                     key=lambda d: (-d["expected_value"], d["capability_id"]))
    return json.dumps({"count": len(impacts), "capabilities": impacts}, indent=2)


@mcp.tool()
def prediction_accuracy() -> str:
    """Prediction-accuracy framework (Phase L, read-only): forecast accuracy, false
    positive/negative rates, calibration error and drift (predicted vs actual recorded)."""
    if (g := _kb_guard()):
        return g
    return json.dumps(PredictionAnalytics().report(), indent=2)


@mcp.tool()
def agent_effectiveness() -> str:
    """Multi-agent simulation (Phase L, read-only): predicted agent effectiveness,
    bottlenecks, capability overlap and redundancy."""
    if (g := _kb_guard()):
        return g
    return json.dumps(AgentSimulation(SimulationContext()).report(), indent=2)


@mcp.tool()
def workflow_optimization(workflow_id: str = "", target: str = "", target_type: str = "web") -> str:
    """Advisory workflow-optimization recommendations (Phase L): remove/reorder steps, add
    capability/verification, increase diversity — WITHOUT mutating any workflow.

    Args:
        workflow_id: an existing runtime workflow
        target: alternatively, the agent plan for this target
        target_type: web|api|cloud|mobile|network|code
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(WorkflowOptimizationAdvisor(SimulationContext()).recommend(
        workflow_id=workflow_id, target=target, target_type=target_type), indent=2)


@mcp.tool()
def decision_health() -> str:
    """Decision-intelligence health (Phase L, read-only): simulation health, prediction
    quality, decision drift, forecast accuracy, and prediction/outcome counts."""
    if (g := _kb_guard()):
        return g
    return json.dumps(PredictionAnalytics().health(), indent=2)


# ── Phase M — Capability Marketplace & Plugin Ecosystem (read-only, advisory) ────────

def _effective_catalog(registry):
    return EffectiveCapabilityCatalog(registry).load()


def _preferred_map(registry):
    return {c["id"]: c["preferred_agent"] for c in registry.plugin_capabilities()
            if c.get("id") and c.get("preferred_agent")}


@mcp.tool()
def plugin_catalog() -> str:
    """List installed/available declarative plugins (Phase M, read-only, no execution).

    Each entry shows id/version/author, capability & tool counts, enabled flag and any
    validation errors. Plugins are declarative data only — never executed."""
    if (g := _kb_guard()):
        return g
    plugins = _PluginRegistry().list_plugins()
    return json.dumps({"count": len(plugins),
                       "enabled": sum(1 for p in plugins if p["enabled"]),
                       "plugins": plugins}, indent=2)


@mcp.tool()
def plugin_summary() -> str:
    """Plugin ecosystem at-a-glance (Phase M, read-only): effective capability/adapter
    composition (core vs plugin) and installed-plugin count."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    return json.dumps({"installed_plugins": len(reg.enabled_plugins()),
                       "composition": eff.composition(),
                       "plugin_ids": sorted(p.plugin_id for p in reg.enabled_plugins())}, indent=2)


@mcp.tool()
def plugin_health() -> str:
    """Derived plugin health (Phase M, read-only, rebuildable): adoption / diversity /
    effectiveness / health from the event-sourced data/plugin_health.db."""
    if (g := _kb_guard()):
        return g
    return json.dumps({"plugins": PluginHealthAnalyzer(_PluginRegistry()).report()}, indent=2)


@mcp.tool()
def plugin_dependencies(plugin_id: str = "") -> str:
    """Capability dependency edges contributed by plugins (Phase M, read-only).

    Args:
        plugin_id: optional — only this plugin's declared edges + plugin version deps
    """
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    if plugin_id:
        pd = reg.get_plugin(plugin_id)
        if pd is None:
            return json.dumps({"success": False, "error": f"unknown plugin: {plugin_id}"})
        return json.dumps({"plugin_id": plugin_id, "dependencies": pd.dependencies,
                           "requires_plugins": pd.requires_plugins}, indent=2)
    return json.dumps({"dependency_edges": reg.plugin_dependency_edges()}, indent=2)


@mcp.tool()
def plugin_capabilities(plugin_id: str = "") -> str:
    """Capabilities a plugin adds to the effective catalog (Phase M, read-only).

    Args:
        plugin_id: optional — only this plugin's capabilities; omit for all plugin capabilities
    """
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    if plugin_id:
        pd = reg.get_plugin(plugin_id)
        if pd is None:
            return json.dumps({"success": False, "error": f"unknown plugin: {plugin_id}"})
        return json.dumps({"plugin_id": plugin_id, "capabilities": pd.capabilities}, indent=2)
    caps = reg.plugin_capabilities()
    return json.dumps({"count": len(caps), "capabilities": caps}, indent=2)


@mcp.tool()
def plugin_coverage() -> str:
    """What the plugin ecosystem adds (Phase M, read-only): capabilities/adapters/agents/
    verification coverage added, plus effective-catalog composition and per-plugin breakdown."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    return json.dumps(EcosystemAnalyzer(reg, eff).report(), indent=2)


@mcp.tool()
def capability_graph() -> str:
    """Capability dependency graph intelligence (Phase M, read-only): edge counts by
    relation, requires-acyclicity + cycles, critical/isolated capabilities, coverage gaps."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    graph = CapabilityDependencyGraph(eff, reg.plugin_dependency_edges()).load()
    return json.dumps(DependencyIntelligence(graph).report(), indent=2)


@mcp.tool()
def dependency_paths(source: str, target: str) -> str:
    """Shortest directed dependency path source→target over requires+enhances (Phase M).

    Args:
        source: starting capability_id
        target: destination capability_id
    """
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    graph = CapabilityDependencyGraph(eff, reg.plugin_dependency_edges()).load()
    path = graph.dependency_paths(source, target)
    return json.dumps({"source": source, "target": target,
                       "path": path, "reachable": bool(path)}, indent=2)


@mcp.tool()
def critical_capabilities() -> str:
    """Most-depended-upon (critical) capabilities by `requires` in-degree (Phase M, read-only)."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    graph = CapabilityDependencyGraph(eff, reg.plugin_dependency_edges()).load()
    return json.dumps({"critical_capabilities": graph.critical_capabilities(),
                       "isolated_capabilities": graph.isolated_capabilities()}, indent=2)


@mcp.tool()
def agent_ownership() -> str:
    """Automatic agent ownership of (plugin) capabilities (Phase M, read-only, advisory):
    per-capability owner, candidates and ownership confidence."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    return json.dumps(AgentOwnershipResolver(eff, preferred=_preferred_map(reg)).resolve(), indent=2)


@mcp.tool()
def ownership_conflicts() -> str:
    """Agent ownership conflicts and gaps (Phase M, read-only, advisory)."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    res = AgentOwnershipResolver(eff, preferred=_preferred_map(reg)).resolve()
    return json.dumps({"ownership_conflicts": res["ownership_conflicts"],
                       "ownership_conflict_count": res["ownership_conflict_count"],
                       "ownership_gaps": res["ownership_gaps"],
                       "ownership_gap_count": res["ownership_gap_count"]}, indent=2)


@mcp.tool()
def ecosystem_summary() -> str:
    """Full ecosystem intelligence (Phase M, read-only, advisory): what plugins add +
    marketplace recommendations (missing plugins, weak areas, ecosystem gaps)."""
    if (g := _kb_guard()):
        return g
    reg = _PluginRegistry()
    eff = _effective_catalog(reg)
    ad = AdapterRegistry(catalog=eff).load()
    return json.dumps({"ecosystem": EcosystemAnalyzer(reg, eff, ad).report(),
                       "marketplace": CapabilityMarketplace(reg, eff, ad).recommend()}, indent=2)


# ── Phase N — Federated Knowledge Exchange & Intelligence Mesh ──────────────────
# All ten tools are read-only/deterministic/advisory and exchange AGGREGATED METADATA
# ONLY. They never share wiki pages, evidence, findings, targets, source identities or
# secrets; never execute peers; and never touch promotion.py / confidence.py / the wiki.
# The derived federation ledger lives in data/federation.db (WAL, rebuildable, disposable).

@mcp.tool()
def federation_peers() -> str:
    """List trusted peer Hydra instances (Phase N, read-only, advisory).

    Federation metadata only — peer name, advertised version/protocol, capability &
    adapter counts, categories, plus DERIVED trust score, health and semantic-version
    compatibility. No credentials or secrets are ever stored."""
    if (g := _kb_guard()):
        return g
    return json.dumps(_FederationRegistry().summary(), indent=2)


@mcp.tool()
def federation_summary() -> str:
    """Federation ledger at-a-glance (Phase N, read-only): event counts by type, distinct
    peers, imported/exported digest counts. Pure function of the append-only data/federation.db."""
    if (g := _kb_guard()):
        return g
    store = _ExchangeStore()
    return json.dumps({**store.summary(),
                       "registry": _FederationRegistry(store).summary()["total_peers"]}, indent=2)


@mcp.tool()
def export_digest(node_name: str = "local", record: bool = False) -> str:
    """Generate this node's anonymized, exchangeable knowledge digest (Phase N, read-only).

    Bundles Capability / Source / Verification / Plugin digests — AGGREGATE METADATA ONLY
    (capability ids and abstract category/method labels + derived scores). Deterministic
    (generated_at fixed) so it is rebuild-identical. No raw knowledge ever leaves the node.

    Args:
        node_name: local node identity used to derive the anonymous origin_peer_id
        record: if True, also append a (derived) digest_export event to data/federation.db
    """
    if (g := _kb_guard()):
        return g
    digest = _DigestGenerator(node_name=node_name).generate(now=0.0)
    if record:
        _ExchangeStore().record("digest_export", digest, peer_id=digest["origin_peer_id"])
    return json.dumps({"success": True, "digest": digest}, indent=2)


@mcp.tool()
def import_digest(digest_json: str, peer_id: str = "") -> str:
    """Import a peer's knowledge digest into the derived federation ledger (Phase N).

    The payload is validated to be aggregated metadata only (raw knowledge is rejected) and
    appended idempotently to data/federation.db — NEVER to the canonical wiki, and never
    influencing promotion or confidence. Re-importing an identical digest is a no-op.

    Args:
        digest_json: the peer's digest envelope as a JSON string (from their export_digest)
        peer_id: optional peer id to attribute the import to (else taken from the envelope)
    """
    if (g := _kb_guard()):
        return g
    try:
        digest = json.loads(digest_json)
    except (ValueError, TypeError) as e:
        return json.dumps({"success": False, "error": f"invalid digest JSON: {e}"})
    if not isinstance(digest, dict):
        return json.dumps({"success": False, "error": "digest must be a JSON object"})
    pid = peer_id or str(digest.get("origin_peer_id", ""))
    try:
        inserted = _ExchangeStore().record("digest_import", digest, peer_id=pid)
    except _FederationSafetyError as e:
        return json.dumps({"success": False, "error": f"rejected (not metadata-only): {e}"})
    return json.dumps({"success": True, "imported": inserted,
                       "deduplicated": not inserted, "peer_id": pid}, indent=2)


@mcp.tool()
def capability_trends() -> str:
    """Federation-wide capability popularity & effectiveness (Phase N, read-only, advisory):
    per-capability adopting-peer count, total exercise, and mean effectiveness across peers."""
    if (g := _kb_guard()):
        return g
    mesh = _IntelligenceMesh()
    return json.dumps({"capabilities": mesh.capability_popularity(),
                       "ecosystem_effectiveness": mesh.ecosystem_effectiveness()}, indent=2)


@mcp.tool()
def verification_trends() -> str:
    """Federation-wide verification trends (Phase N, read-only, advisory): mean method and
    evidence-class success rates aggregated across all imported digests."""
    if (g := _kb_guard()):
        return g
    return json.dumps(_IntelligenceMesh().verification_trends(), indent=2)


@mcp.tool()
def source_trends() -> str:
    """Federation-wide source-CATEGORY trends (Phase N, read-only, advisory): mean
    effectiveness/trust/novelty per source category. No source identities are exchanged."""
    if (g := _kb_guard()):
        return g
    return json.dumps({"source_categories": _IntelligenceMesh().source_category_trends()}, indent=2)


@mcp.tool()
def federation_consensus(capability_id: str = "") -> str:
    """Advisory federation consensus (Phase N, read-only): consensus confidence, disagreement,
    diversity and blended federation confidence — for one capability or the whole federation.

    ADVISORY ONLY — never influences promotion, confidence bands, or wiki state.

    Args:
        capability_id: optional — score just this capability; omit for the full report
    """
    if (g := _kb_guard()):
        return g
    ce = _ConsensusEngine()
    if capability_id:
        return json.dumps(ce.capability_consensus(capability_id), indent=2)
    return json.dumps(ce.consensus_report(), indent=2)


@mcp.tool()
def ecosystem_opportunities() -> str:
    """Advisory federation marketplace (Phase N, read-only): capabilities popular elsewhere
    but missing locally, widely-adopted plugins, underrepresented categories + recommendations.
    Discovery only — nothing is installed, executed, or written."""
    if (g := _kb_guard()):
        return g
    return json.dumps(_FederationMarketplace().ecosystem_opportunities(), indent=2)


@mcp.tool()
def federation_health() -> str:
    """Federation-wide health (Phase N, read-only, advisory): contributing peers, imported
    digests, ecosystem effectiveness, verification effectiveness, registry trust + consensus."""
    if (g := _kb_guard()):
        return g
    store = _ExchangeStore()
    mesh = _IntelligenceMesh(store)
    reg = _FederationRegistry(store)
    consensus = _ConsensusEngine(store).consensus_report(top=5)
    return json.dumps({
        "mesh": mesh.federation_health(),
        "registry": {k: v for k, v in reg.summary().items() if k != "peers"},
        "mean_federation_confidence": consensus["mean_federation_confidence"],
        "advisory": True,
    }, indent=2)


# ── Phase O — Temporal Knowledge Intelligence (derived, advisory, deterministic) ──
# All six tools are read-only/deterministic/advisory and built ENTIRELY from the existing
# derived event logs (source/verification/tool-health/plugin-health/decision/federation).
# They never read or write the canonical wiki and never touch promotion.py / confidence.py.
# `now` is an optional injected reference time for determinism; <=0 means "use newest event".
def _temporal_now(now: float):
    return None if now is None or now <= 0 else float(now)


@mcp.tool()
def temporal_summary(now: float = 0.0) -> str:
    """Temporal knowledge overview (Phase O, read-only, advisory): temporal-health, strongest/
    weakest trends, emerging/declining capabilities, decay & anomaly counts, recommendations.

    Args:
        now: optional reference timestamp for deterministic bucketing (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_TemporalIntelligence().temporal_summary(_temporal_now(now)), indent=2)


@mcp.tool()
def temporal_trends(domain: str = "", now: float = 0.0) -> str:
    """Temporal trends + momentum (Phase O, read-only, advisory): rising/stable/declining per
    entity with slope, momentum and the bucket series, for capability/adapter/agent/plugin/
    source/verification.

    Args:
        domain: optional single domain (e.g. "capability"); omit for all trend domains
        now: optional reference timestamp for deterministic bucketing (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    ref = _temporal_now(now)
    ctx = _TemporalContext().load()
    trend, mom = _TrendAnalyzer(ctx), _MomentumAnalyzer(ctx)
    if domain:
        return json.dumps({"domain": domain, "trends": trend.domain_trends(domain, ref),
                           "momentum": mom.domain_momentum(domain, ref)}, indent=2)
    return json.dumps({"trends": trend.trends(ref), "momentum": mom.momentum(ref)}, indent=2)


@mcp.tool()
def temporal_forecast(domain: str = "", now: float = 0.0, horizon: int = 3) -> str:
    """Deterministic bounded forecasts (Phase O, read-only, advisory): future capability
    utilization, verification coverage, source diversity, plugin adoption. Moving-average +
    linear slope; never stochastic.

    Args:
        domain: optional single domain to forecast; omit for the four standard signals
        now: optional reference timestamp (<=0 = newest event)
        horizon: number of future buckets to project (default 3)
    """
    if (g := _kb_guard()):
        return g
    ref = _temporal_now(now)
    fc = _TemporalForecast(_TemporalContext().load())
    if domain:
        return json.dumps({"domain_forecast": fc.domain_forecast(domain, ref, horizon),
                           "entity_forecast": fc.entity_forecast(domain, ref, horizon)}, indent=2)
    return json.dumps(fc.report(ref, horizon), indent=2)


@mcp.tool()
def temporal_decay(now: float = 0.0) -> str:
    """Temporal decay findings (Phase O, read-only, advisory): stale capabilities/adapters/
    plugins/verification methods ranked by severity, each with rationale + suggested action.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_TemporalIntelligence().decay_forecast(_temporal_now(now)), indent=2)


@mcp.tool()
def temporal_anomalies(now: float = 0.0) -> str:
    """Temporal anomalies (Phase O, read-only, advisory): spikes, drops, inactivity and
    concentration across domains. Findings only — no alerts, no side effects.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_TemporalIntelligence().anomaly_report(_temporal_now(now)), indent=2)


@mcp.tool()
def temporal_health(now: float = 0.0) -> str:
    """Temporal-health score (Phase O, read-only, advisory): 0-100 blend rewarding rising/active
    knowledge and penalizing decay + anomalies. Never alters confidence/promotion.

    Args:
        now: optional reference timestamp (<=0 = newest event)
    """
    if (g := _kb_guard()):
        return g
    return json.dumps(_TemporalIntelligence().temporal_health(_temporal_now(now)), indent=2)


@mcp.tool()
def ingest_report(path: str = "", text: str = "", source_url: str = "",
                  target: str = "", title: str = "") -> str:
    """Report Intelligence: distill a disclosed report/writeup into the knowledge graph.

    Extracts reusable attacker knowledge (root cause, trust-boundary failure,
    exploitation sequence, escalation, impact, attacker assumptions), assigns a
    deterministic 1-10 `learning_score`, and writes cross-linked canonical
    `report` + `intel` wiki pages. Offline-first; only `report`/`intel` pages are
    ever created (no findings/patterns/chains); missing technique/pattern links
    are recorded as `unresolved_references`, never auto-created.

    Args:
        path: path to a local report file (read offline)
        text: raw report content (alternative to path)
        source_url: original disclosure URL (for provenance / slug identity)
        target: program/asset slug the report concerns (e.g. "vk")
        title: report title (used for the deterministic page slug)
    """
    if (g := _kb_guard()):
        return g
    if not (path or text):
        return json.dumps({"success": False, "error": "provide 'path' or 'text'"})
    src = ReportSource(path=path, text=text, source_url=source_url, target=target, title=title)
    try:
        extracted = ReportIntelligencePipeline(WikiStore()).ingest(src)
    except FileNotFoundError:
        return json.dumps({"success": False, "error": f"report file not found: {path}"})
    return json.dumps({"success": True, **extracted.to_dict()}, indent=2)


@mcp.tool()
def report_lookup(slug: str) -> str:
    """Look up an ingested report page: metadata, learning_score, and links."""
    if (g := _kb_guard()):
        return g
    store = WikiStore()
    page = store.get(slug, _NodeType.REPORT)
    if page is None:
        return json.dumps({"success": False, "error": f"no report page for: {slug}"})
    return json.dumps({
        "success": True, "slug": slug, "path": str(page.path),
        "learning_score": page.meta.get("learning_score"),
        "learning_score_rationale": page.meta.get("learning_score_rationale"),
        "vuln_class": page.meta.get("vuln_class"),
        "severity": page.meta.get("severity"),
        "unresolved_references": page.meta.get("unresolved_references", []),
        "links": [s for s in page.links],
    }, indent=2)


@mcp.tool()
def list_reports(min_learning_score: int = 0) -> str:
    """List ingested report pages ranked by learning_score (high-value learning first).

    Args:
        min_learning_score: only include reports scoring at or above this (0-10)
    """
    if (g := _kb_guard()):
        return g
    store = WikiStore()
    rows = []
    for page in store.iter_pages(_NodeType.REPORT):
        score = page.meta.get("learning_score", 0)
        try:
            score = int(score)
        except (TypeError, ValueError):
            score = 0
        if score >= min_learning_score:
            rows.append({"slug": page.slug, "learning_score": score,
                         "vuln_class": page.meta.get("vuln_class"),
                         "severity": page.meta.get("severity")})
    # Deterministic order: highest score first, ties broken by slug.
    rows.sort(key=lambda r: (-r["learning_score"], r["slug"]))
    return json.dumps({"count": len(rows), "reports": rows}, indent=2)


def _policy(online: bool):
    """Build an ExecutionPolicy. Online keys come from HYDRA_SOURCE_KEYS (comma-separated)."""
    if not online:
        return ExecutionPolicy.offline()
    keys = {k.strip() for k in os.environ.get("HYDRA_SOURCE_KEYS", "").split(",") if k.strip()}
    return ExecutionPolicy.online(available_keys=keys)


# ══════════════════════════════════════════════
#  SERVER ENTRY POINT
# ══════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HYDRA MCP Security Server")
    parser.add_argument(
        "--transport", choices=["stdio", "sse"], default="stdio",
        help="MCP transport: stdio (local) or sse (HTTP for remote clients)"
    )
    parser.add_argument("--port", type=int, default=8900, help="Port for SSE transport")
    args = parser.parse_args()

    print("[HYDRA] MCP Security Server starting...", file=sys.stderr)
    print(f"[HYDRA] Transport: {args.transport}", file=sys.stderr)
    print("[HYDRA] Tools available for any MCP-compatible AI agent", file=sys.stderr)

    if args.transport == "sse":
        mcp.run(transport="sse", port=args.port)
    else:
        mcp.run(transport="stdio")
