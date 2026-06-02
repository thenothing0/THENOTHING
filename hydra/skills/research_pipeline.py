"""
Research → skill template pipeline (offline, user-supplied text only).

Does not scrape third-party sites by default. Safe for authorized research notes.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_cve_ids(text: str) -> List[str]:
    return sorted(set(m.group(0).upper() for m in _CVE_RE.finditer(text or "")))


def research_text_to_skill_template(
    *,
    name: str,
    body: str,
    category: str = "web",
    mcp_tools: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Build a YAML-serializable skill dict from pasted research / writeup summary.

    Caller is responsible for legal use of `body` (licensing, scope, etc.).
    """
    cves = extract_cve_ids(body)
    return {
        "id": re.sub(r"[^a-z0-9_]+", "_", name.lower()).strip("_") or "generated_skill",
        "name": name,
        "category": category,
        "version": "0.1-generated",
        "description": (body[:400] + "…") if len(body) > 400 else body,
        "triggers": ["research_ingest", "cve_reference"] if cves else ["research_ingest"],
        "reasoning_heuristics": [
            "Map claimed vulnerability class to testable hypotheses.",
            "Derive minimal reproduction aligned with program rules of engagement.",
            "Prefer passive signals before active probes.",
        ],
        "exploit_hypotheses": [
            {
                "id": "h0",
                "title": "Pattern match from research",
                "description": "Validate whether the described conditions hold on the in-scope target.",
                "test_steps": [
                    "Confirm component versions and exposure surface.",
                    "Cross-check with tool findings; reject if only version banner match.",
                ],
                "cwe": "",
            }
        ],
        "mcp_tools": mcp_tools or ["whatweb_detect", "nuclei_scan", "httpx_probe"],
        "validation": {
            "require_replay": True,
            "rules": [
                {
                    "name": "non_duplicate",
                    "check_type": "manual_triage",
                    "expected": "unique_issue",
                    "confidence_boost": 0.1,
                }
            ],
        },
        "references": cves,
        "confidence_rules": {"minimum_score": 0.55},
        "reporting_guidance": [
            "Structured impact, clear repro, remediation, and safe harbor compliance.",
        ],
    }
