"""Evidence extraction: tool output → draft findings (Phase 3 automation)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

# Tool → the vuln_class its coverage tuple records / its findings default to.
_TOOL_VULN_CLASS = {
    "nuclei": "cve", "nuclei_scan": "cve", "sqlmap": "sqli", "sqlmap_scan": "sqli",
    "dalfox": "xss", "dalfox_scan": "xss", "gxss": "xss", "gxss_check": "xss",
    "subzy": "subdomain_takeover", "subzy_takeover": "subdomain_takeover",
    "ffuf": "content_discovery", "dirsearch": "content_discovery",
    "katana": "recon", "subfinder": "recon", "httpx": "recon", "whatweb": "fingerprint",
    "attack_scan": "injection", "shell_exec": "manual",
}


def vuln_class_for_tool(tool: str) -> str:
    return _TOOL_VULN_CLASS.get(tool, tool.split("_")[0])


@dataclass
class EvidenceFinding:
    title: str
    vuln_class: str
    severity: str
    url: str = ""


# nuclei: [template-id] [protocol] [severity] url
_NUCLEI_RE = re.compile(
    r"\[(?P<tid>[a-z0-9][\w.-]+)\]\s*\[[a-z]+\]\s*\[(?P<sev>info|low|medium|high|critical)\]\s*(?P<url>\S+)",
    re.I)
# subzy: [ VULNERABLE ] ... url
_SUBZY_RE = re.compile(r"\[\s*VULNERABLE\s*\][^\n]*?(https?://\S+)", re.I)
# generic scanner verdict
_GENERIC_VULN_RE = re.compile(r"\bVULNERABLE\b[^\n]*?(https?://\S+)?", re.I)
_SQLI_RE = re.compile(r"\b(sql syntax|sqlstate|unclosed quotation|ORA-\d+|is vulnerable)\b", re.I)


def extract_findings(tool: str, output: str) -> List[EvidenceFinding]:
    """Parse a tool's stdout into draft findings. Conservative: only emits a
    finding when the output carries a recognized vulnerability signal."""
    out = output or ""
    findings: List[EvidenceFinding] = []
    seen = set()

    for m in _NUCLEI_RE.finditer(out):
        sev = m.group("sev").lower()
        if sev == "info":
            continue  # info-level nuclei matches are not findings
        key = (m.group("tid"), m.group("url"))
        if key in seen:
            continue
        seen.add(key)
        findings.append(EvidenceFinding(
            title=f"{m.group('tid')} on {m.group('url')}",
            vuln_class=m.group("tid").split("-")[0], severity=sev, url=m.group("url")))

    for m in _SUBZY_RE.finditer(out):
        url = m.group(1)
        if ("takeover", url) in seen:
            continue
        seen.add(("takeover", url))
        findings.append(EvidenceFinding(
            title=f"Subdomain takeover at {url}", vuln_class="subdomain_takeover",
            severity="high", url=url))

    if not findings:
        sm = _SQLI_RE.search(out)
        if sm:
            findings.append(EvidenceFinding(
                title="Possible SQL injection (error signature)", vuln_class="sqli",
                severity="high"))
        elif tool not in ("subfinder", "httpx", "katana", "whatweb", "subzy_takeover") \
                and _GENERIC_VULN_RE.search(out):
            findings.append(EvidenceFinding(
                title=f"{tool}: vulnerability signal in output", vuln_class=vuln_class_for_tool(tool),
                severity="medium"))
    return findings
