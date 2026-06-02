"""Shared seed wiki for Phase-C discovery tests — deterministic, programmatic, offline."""

import pytest

from hydra.knowledge.schema import NodeType
from hydra.knowledge.wiki_store import WikiStore


def build_seed(root) -> WikiStore:
    """A deterministic wiki exercising every discovery path.

    - idor: two VALIDATED findings (a,b) sharing tags + target  → pattern (high)
    - idor: one REJECTED finding                                → conflicting evidence
    - idor: one HYPOTHESIS                                       → excluded (zero weight)
    - ssrf: one validated finding + one report-derived intel
            (intel body describes escalation)                   → pattern (medium)
    - xss : a single validated finding                          → NO pattern (1 source)
    - acme target shared by the idor/ssrf findings              → chain (shared_target)
    """
    ws = WikiStore(root)
    ws.upsert(NodeType.TARGET, "acme", {"tags": ["t"]}, "# acme\n")

    ws.upsert(NodeType.FINDING, "acme-idor-a",
              {"tags": ["idor", "api"], "status": "submitted", "target": "[[acme]]",
               "severity": "P2"},
              "# A\nInsecure direct object reference in the api. Broken access leads to "
              "privilege escalation. [[idor-pattern]]\n")
    ws.upsert(NodeType.FINDING, "acme-idor-b",
              {"tags": ["idor", "api"], "status": "confirmed", "target": "[[acme]]",
               "severity": "P3"},
              "# B\nBroken access / idor on another endpoint; admin access via escalation.\n")
    ws.upsert(NodeType.FINDING, "acme-idor-rejected",
              {"tags": ["idor"], "status": "rejected", "target": "[[acme]]"},
              "# Rejected\nidor that was a duplicate.\n")
    ws.upsert(NodeType.HYPOTHESIS, "acme-idor-hyp",
              {"tags": ["idor"], "status": "open"},
              "# Hyp\nMaybe idor here too — unvalidated.\n")

    ws.upsert(NodeType.FINDING, "acme-ssrf",
              {"tags": ["ssrf", "api"], "status": "submitted", "target": "[[acme]]",
               "severity": "P2"},
              "# SSRF\nServer side request forgery reaching internal metadata.\n")
    ws.upsert(NodeType.INTEL, "ssrf-writeup-intel",
              {"tags": ["intel", "auto", "report-derived"], "sources": ["https://x/report"]},
              "# SSRF writeup — actionable intelligence\nServer side request forgery with "
              "privilege escalation to admin. Distilled from report [[ssrf-writeup]].\n")

    ws.upsert(NodeType.FINDING, "acme-xss",
              {"tags": ["xss"], "status": "submitted", "target": "[[acme]]"},
              "# XSS\nReflected cross site scripting.\n")
    return ws


@pytest.fixture
def seed_wiki(tmp_path):
    return build_seed(tmp_path / "wiki")
