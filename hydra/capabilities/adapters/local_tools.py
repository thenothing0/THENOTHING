"""
Local-tool source adapter — wraps existing MCP tools as recon sources.

Lets capability sources backed by a local binary (subfinder, amass, ...) run
through the already-hardened `mcp_server` boundary. In tests/CI the fake-tool
doubles on PATH make these deterministic and offline; with real Kali tools
installed they produce live results. mcp_server is imported lazily so importing
this module never drags in the MCP server.
"""

from __future__ import annotations

import json
from typing import Callable, Dict, List

from hydra.capabilities.sources import Source

# source id -> (mcp tool function name, json key holding the list of values)
_SUBDOMAIN_TOOLS: Dict[str, tuple] = {
    "source.subfinder": ("subfinder_scan", "subdomains"),
    "source.amass": ("amass_enum", "subdomains"),
}
_URL_TOOLS: Dict[str, tuple] = {
    "source.gau": ("gau_urls", "urls"),
    "source.katana": ("katana_crawl", "endpoints"),
}


def supports(source: Source) -> bool:
    return source.id in _SUBDOMAIN_TOOLS or source.id in _URL_TOOLS


def collect(source: Source, domain: str) -> List[str]:
    mapping = _SUBDOMAIN_TOOLS.get(source.id) or _URL_TOOLS.get(source.id)
    if not mapping:
        return []
    fn_name, key = mapping
    try:
        import mcp_server  # lazy: avoids importing the server unless actually used
        fn: Callable = getattr(mcp_server, fn_name)
        raw = json.loads(fn(domain))
    except Exception:
        return []
    if raw.get("rejected") or not isinstance(raw, dict):
        return []
    vals = raw.get(key) or []
    return [str(v).strip() for v in vals if str(v).strip()]
