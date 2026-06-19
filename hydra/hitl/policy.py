"""Risk classification + approval policy + emergency stop."""

from __future__ import annotations

import re
from typing import Dict, List, Optional


class RiskLevel:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    PROHIBITED = "prohibited"


class Decision:
    ALLOW_ONCE = "allow-once"
    ALLOW_SESSION = "allow-session"
    ALLOW_WORKFLOW = "allow-workflow"
    ALWAYS_ALLOW = "always-allow"      # operator/YOLO friction skip
    DENY = "deny"
    EMERGENCY_STOP = "emergency-stop"


_RANK = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2,
         RiskLevel.CRITICAL: 3, RiskLevel.PROHIBITED: 4}

# Tool → baseline risk. Tools not listed default to MEDIUM (active by assumption).
RISK_OF_TOOL: Dict[str, str] = {}


def _seed_risk() -> None:
    low = ["get_findings", "finding_list", "coverage_summary", "coverage_next", "list_reports",
           "report_lookup", "kb_recall", "burp_status", "burp_requests", "burp_endpoints",
           "burp_timeline", "learn_search", "learn_stats", "skill_list", "skill_verify",
           "check_tools", "asset_lookup", "graph_neighbors", "get_findings"]
    medium = ["subfinder_scan", "amass_enum", "httpx_probe", "katana_crawl", "gau_urls",
              "hakrawler_crawl", "dnsx_resolve", "subzy_takeover", "whatweb_detect",
              "wafw00f_detect", "nuclei_scan", "dalfox_scan", "gxss_check", "ffuf_fuzz",
              "dirsearch_scan", "nmap_scan", "browser_crawl", "attack_scan", "attack_plan",
              "waf_bypass", "burp_ingest_sitemap", "coverage_record"]
    high = ["attack_execute", "attack_chain_execute", "attack_api", "attack_oob_test",
            "attack_stored", "attack_privesc", "sqlmap_scan", "shell_exec",
            "enum4linux_scan", "smbmap_scan", "ldapsearch_query"]
    critical = ["netexec_scan", "secretsdump_run", "bloodhound_collect", "hashcat_crack",
                "john_crack"]
    for t in low:
        RISK_OF_TOOL[t] = RiskLevel.LOW
    for t in medium:
        RISK_OF_TOOL[t] = RiskLevel.MEDIUM
    for t in high:
        RISK_OF_TOOL[t] = RiskLevel.HIGH
    for t in critical:
        RISK_OF_TOOL[t] = RiskLevel.CRITICAL


_seed_risk()

# Argument heuristics that ELEVATE risk (never lower it).
_SCANNER_RE = re.compile(r"\b(nuclei|sqlmap|ffuf|masscan|hydra|medusa|nikto)\b", re.I)
# Tokens that, in a shell command, indicate an absolute prohibition (DoS/destruct).
# Word-based tokens are \b-anchored; symbol patterns (fork bomb) are left
# unanchored because a leading ':' is a non-word char and would defeat \b.
_PROHIBITED_RE = re.compile(
    r"(?:\b(?:slowloris|t50|mhddos|goldeneye|mkfs)\b|hping3\s+--flood|"
    r":\(\)\s*\{|\bshred\s+-)", re.I)


def classify_risk(tool: str, args: Optional[Dict] = None) -> str:
    """Classify a tool call's risk level. Arg heuristics can only raise it."""
    args = args or {}
    base = RISK_OF_TOOL.get(tool, RiskLevel.MEDIUM)
    if tool in ("shell_exec",):
        cmd = str(args.get("command", ""))
        if _PROHIBITED_RE.search(cmd):
            return RiskLevel.PROHIBITED
        if _SCANNER_RE.search(cmd):
            base = _max(base, RiskLevel.HIGH)
    # netexec with a code-exec command is CRITICAL (already), keep as-is.
    return base


def _max(a: str, b: str) -> str:
    return a if _RANK[a] >= _RANK[b] else b


class ApprovalPolicy:
    """Decides what decisions are offered (or auto-taken) for a tool call.

    operator_mode == True  → friction auto-approved up to CRITICAL.
    Emergency stop hard-denies everything until reset.
    """

    def __init__(self, operator_mode: bool = False):
        self.operator_mode = operator_mode
        self._emergency = False
        self._workflow_grants: Dict[str, set] = {}   # workflow_run_id -> {tool}

    # ── emergency stop ───────────────────────────────────────────────────────────
    def emergency_stop(self) -> None:
        self._emergency = True

    def reset_emergency(self) -> None:
        self._emergency = False

    @property
    def stopped(self) -> bool:
        return self._emergency

    # ── workflow-scoped grants ───────────────────────────────────────────────────
    def grant_workflow(self, run_id: str, tool: str) -> None:
        self._workflow_grants.setdefault(run_id, set()).add(tool)

    def clear_workflow(self, run_id: str) -> None:
        self._workflow_grants.pop(run_id, None)

    # ── the decision ─────────────────────────────────────────────────────────────
    def evaluate(self, tool: str, args: Optional[Dict] = None,
                 workflow_run_id: str = "") -> Dict:
        """Return {risk, auto, decision?, options[], hard_deny}.

        `auto`/`decision` set ⇒ no prompt needed. `options` is the menu to show
        otherwise. `hard_deny` ⇒ refuse regardless of mode.
        """
        risk = classify_risk(tool, args)
        if self._emergency:
            return {"risk": risk, "hard_deny": True, "auto": True,
                    "decision": Decision.DENY, "reason": "EMERGENCY STOP active", "options": []}
        if risk == RiskLevel.PROHIBITED:
            return {"risk": risk, "hard_deny": True, "auto": True,
                    "decision": Decision.DENY,
                    "reason": "absolute prohibition — never allowed", "options": []}

        # Existing workflow grant satisfies HIGH-tier allow-workflow.
        if (workflow_run_id and risk == RiskLevel.HIGH
                and tool in self._workflow_grants.get(workflow_run_id, set())):
            return {"risk": risk, "auto": True, "decision": Decision.ALLOW_WORKFLOW,
                    "reason": "covered by an existing allow-workflow grant", "options": [],
                    "hard_deny": False}

        # Operator/YOLO: auto-approve friction up to CRITICAL.
        if self.operator_mode:
            return {"risk": risk, "auto": True, "decision": Decision.ALWAYS_ALLOW,
                    "reason": "operator mode (friction auto-approved; scope gate + "
                              "prohibitions still hard)", "options": [], "hard_deny": False}

        # Interactive: the menu depends on tier.
        options = {
            RiskLevel.LOW: [],  # auto
            RiskLevel.MEDIUM: [Decision.ALLOW_ONCE, Decision.ALLOW_SESSION, Decision.DENY],
            RiskLevel.HIGH: [Decision.ALLOW_ONCE, Decision.ALLOW_WORKFLOW, Decision.DENY],
            RiskLevel.CRITICAL: [Decision.ALLOW_ONCE, Decision.DENY, Decision.EMERGENCY_STOP],
        }[risk]
        if risk == RiskLevel.LOW:
            return {"risk": risk, "auto": True, "decision": Decision.ALLOW_ONCE,
                    "reason": "low-risk read/passive — auto-allowed (logged)",
                    "options": [], "hard_deny": False}
        return {"risk": risk, "auto": False, "options": options, "hard_deny": False,
                "reason": f"{risk}-risk — operator decision required"}
