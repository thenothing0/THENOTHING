"""
╔══════════════════════════════════════════════════════════════╗
║  Autonomous Hunt Engine — Self-Directed Vulnerability Hunting║
║  Adaptive loops, vuln-class strategies, success tracking     ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.hunt")


class HuntStatus(str, Enum):
    IDLE = "idle"
    HUNTING = "hunting"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnClass(str, Enum):
    SSRF = "ssrf"
    IDOR = "idor"
    XSS = "xss"
    SQLI = "sqli"
    OAUTH = "oauth"
    AUTHZ = "authz"
    RCE = "rce"
    LFI = "lfi"
    SSTI = "ssti"
    CORS = "cors"
    OPEN_REDIRECT = "open_redirect"
    RACE_CONDITION = "race_condition"
    BUSINESS_LOGIC = "business_logic"
    INFO_DISCLOSURE = "info_disclosure"
    AUTO = "auto"


@dataclass
class HuntCycle:
    cycle_id: int
    vuln_class: str
    targets_tested: int = 0
    findings: List[Dict] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0
    duration_s: float = 0
    success: bool = False


@dataclass
class HuntSession:
    target: str
    session_id: str = ""
    status: HuntStatus = HuntStatus.IDLE
    mode: str = "normal"  # normal | aggressive | stealth
    cycles: List[HuntCycle] = field(default_factory=list)
    total_findings: int = 0
    vuln_classes_tested: List[str] = field(default_factory=list)
    success_rate: float = 0.0
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0


HUNT_STRATEGIES: Dict[str, Dict[str, Any]] = {
    VulnClass.SSRF: {
        "name": "SSRF Hunter",
        "tools": ["nuclei", "ffuf"],
        "nuclei_tags": ["ssrf"],
        "recon_needs": ["endpoints", "parameters"],
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80",
            "http://[::1]:80",
            "http://0x7f000001",
        ],
        "parameter_targets": ["url", "uri", "path", "dest", "redirect", "callback",
                              "next", "data", "reference", "site", "html", "val",
                              "link", "src", "img", "feed", "to", "out", "view"],
        "priority": 0,
    },
    VulnClass.IDOR: {
        "name": "IDOR Hunter",
        "tools": ["nuclei", "httpx"],
        "nuclei_tags": ["idor"],
        "recon_needs": ["endpoints", "auth_endpoints"],
        "techniques": ["sequential_id", "uuid_bruteforce", "parameter_swap",
                       "path_traversal", "method_change"],
        "priority": 0,
    },
    VulnClass.XSS: {
        "name": "XSS Hunter",
        "tools": ["nuclei", "katana"],
        "nuclei_tags": ["xss"],
        "recon_needs": ["endpoints", "parameters", "forms"],
        "payloads": [
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "'-alert(1)-'",
        ],
        "priority": 1,
    },
    VulnClass.SQLI: {
        "name": "SQLi Hunter",
        "tools": ["nuclei"],
        "nuclei_tags": ["sqli"],
        "recon_needs": ["endpoints", "parameters"],
        "payloads": ["'", "\"", "' OR 1=1--", "1 AND 1=1", "1' AND '1'='1"],
        "parameter_targets": ["id", "user", "name", "page", "search", "query",
                              "cat", "dir", "action", "board", "date", "detail",
                              "file", "download", "path", "folder", "prefix",
                              "include", "inc", "locate", "show", "doc", "site",
                              "type", "view", "content", "layout", "mod", "conf"],
        "priority": 1,
    },
    VulnClass.OAUTH: {
        "name": "OAuth/Auth Flow Hunter",
        "tools": ["nuclei", "httpx"],
        "nuclei_tags": ["oauth", "token"],
        "recon_needs": ["auth_endpoints", "oauth_endpoints"],
        "checks": ["token_leakage", "state_fixation", "redirect_uri_bypass",
                   "scope_escalation", "pkce_absence", "implicit_flow_abuse"],
        "priority": 0,
    },
    VulnClass.AUTHZ: {
        "name": "Authorization Bypass Hunter",
        "tools": ["nuclei", "httpx"],
        "nuclei_tags": ["auth-bypass"],
        "recon_needs": ["endpoints", "admin_endpoints"],
        "techniques": ["path_traversal", "method_override", "header_injection",
                       "role_escalation", "missing_function_check"],
        "priority": 0,
    },
    VulnClass.SSTI: {
        "name": "SSTI Hunter",
        "tools": ["nuclei"],
        "nuclei_tags": ["ssti"],
        "recon_needs": ["endpoints", "parameters"],
        "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{7*7}"],
        "priority": 1,
    },
    VulnClass.CORS: {
        "name": "CORS Misconfiguration Hunter",
        "tools": ["nuclei"],
        "nuclei_tags": ["cors"],
        "recon_needs": ["endpoints"],
        "checks": ["null_origin", "wildcard_origin", "subdomain_reflection",
                   "credential_leakage"],
        "priority": 2,
    },
    VulnClass.OPEN_REDIRECT: {
        "name": "Open Redirect Hunter",
        "tools": ["nuclei"],
        "nuclei_tags": ["redirect"],
        "recon_needs": ["endpoints", "parameters"],
        "parameter_targets": ["url", "redirect", "next", "dest", "redir",
                              "return", "returnTo", "go", "checkout_url",
                              "continue", "return_path"],
        "payloads": ["//evil.com", "https://evil.com", "/\\evil.com",
                    "//evil%00.com", "https:evil.com"],
        "priority": 2,
    },
    VulnClass.INFO_DISCLOSURE: {
        "name": "Information Disclosure Hunter",
        "tools": ["nuclei", "ffuf", "dirsearch"],
        "nuclei_tags": ["exposure", "disclosure"],
        "recon_needs": ["endpoints"],
        "paths": ["/.env", "/.git/config", "/debug", "/actuator", "/graphql",
                  "/.well-known/", "/server-status", "/phpinfo.php",
                  "/wp-json/wp/v2/users", "/api/swagger.json",
                  "/.DS_Store", "/backup.sql", "/database.sql"],
        "priority": 1,
    },
}


class HuntEngine:
    """
    Autonomous Hunt Engine.
    
    Runs self-directed vulnerability hunting loops with
    adaptive strategy selection, success tracking, and
    automatic escalation when high-severity findings emerge.
    """

    def __init__(self, coordinator=None, planner=None, mcp_client=None,
                 scope_engine=None, artifact_store=None, semantic_memory=None):
        self.coordinator = coordinator
        self.planner = planner
        self.mcp = mcp_client
        self.scope = scope_engine
        self.artifacts = artifact_store
        self.memory = semantic_memory
        self._active_sessions: Dict[str, HuntSession] = {}
        self._hunt_history: List[Dict] = []

    async def hunt(self, target: str, vuln_class: str = "auto",
                   mode: str = "normal", max_cycles: int = 10,
                   timeout_minutes: int = 30) -> HuntSession:
        """Run an autonomous hunt session."""
        session = HuntSession(
            target=target,
            session_id=f"hunt-{int(time.time())}",
            mode=mode,
            status=HuntStatus.HUNTING,
        )
        self._active_sessions[session.session_id] = session
        logger.info(f"🎯 Hunt started: {target} | class={vuln_class} | mode={mode}")

        # Scope check
        if self.scope and self.scope.is_loaded:
            check = self.scope.validate_target(target)
            if not check.allowed:
                logger.error(f"🚫 Hunt blocked — target out of scope: {check.reason}")
                session.status = HuntStatus.FAILED
                return session

        # Determine which vuln classes to hunt
        if vuln_class == "auto":
            classes = await self._select_priority_classes(target)
        else:
            classes = [vuln_class]

        deadline = time.time() + (timeout_minutes * 60)
        cycle_num = 0

        for vc in classes:
            if cycle_num >= max_cycles or time.time() > deadline:
                break

            strategy = HUNT_STRATEGIES.get(vc)
            if not strategy:
                continue

            cycle = HuntCycle(cycle_id=cycle_num, vuln_class=vc)
            logger.info(f"🔄 Hunt cycle {cycle_num}: {strategy['name']}")

            try:
                findings = await self._execute_hunt_cycle(target, vc, strategy, mode)
                cycle.findings = findings
                cycle.targets_tested = max(1, len(findings))
                cycle.success = len(findings) > 0
                cycle.ended_at = time.time()
                cycle.duration_s = cycle.ended_at - cycle.started_at
            except Exception as e:
                logger.error(f"Hunt cycle {cycle_num} failed: {e}")
                cycle.ended_at = time.time()

            session.cycles.append(cycle)
            session.total_findings += len(cycle.findings)
            session.vuln_classes_tested.append(vc)
            cycle_num += 1

            # Adaptive: if high-severity found, escalate
            if any(f.get("severity", "").lower() in ("critical", "high") for f in cycle.findings):
                logger.info(f"🔥 High-severity finding! Escalating hunt...")
                if self.planner:
                    await self.planner.replan(
                        plan_id=session.session_id,
                        findings=cycle.findings,
                        reason="high_severity_finding",
                    )

            # Save artifacts
            if self.artifacts:
                self.artifacts.save_parsed_output(
                    target, "scans", f"hunt_cycle_{cycle_num}",
                    {"cycle": cycle_num, "class": vc, "findings": cycle.findings}
                )

        # Finalize session
        session.status = HuntStatus.COMPLETED
        session.ended_at = time.time()
        total_cycles = len(session.cycles)
        successful = sum(1 for c in session.cycles if c.success)
        session.success_rate = round(successful / max(total_cycles, 1) * 100, 1)

        logger.info(
            f"✅ Hunt complete: {session.total_findings} findings, "
            f"{session.success_rate}% success rate ({successful}/{total_cycles} cycles)"
        )

        # Store in memory for future hunts
        if self.memory:
            try:
                await self.memory.store(
                    content=f"Hunt session on {target}: {session.total_findings} findings, "
                            f"classes: {session.vuln_classes_tested}, "
                            f"success_rate: {session.success_rate}%",
                    metadata={"type": "hunt_session", "target": target,
                              "findings": session.total_findings},
                )
            except Exception:
                pass

        self._hunt_history.append({
            "session_id": session.session_id, "target": target,
            "findings": session.total_findings, "success_rate": session.success_rate,
            "classes": session.vuln_classes_tested, "timestamp": time.time(),
        })

        return session

    async def _select_priority_classes(self, target: str) -> List[str]:
        """AI-driven vuln class selection based on target profile."""
        # Check memory for what worked on similar targets
        if self.memory:
            try:
                similar = await self.memory.search(
                    query=f"successful hunt strategies for {target}",
                    n_results=5,
                )
                # Extract successful vuln classes from memory
                if similar:
                    logger.info(f"📚 Found {len(similar)} similar hunt sessions in memory")
            except Exception:
                pass

        # Default priority order based on bug bounty success rates
        return [
            VulnClass.SSRF, VulnClass.IDOR, VulnClass.AUTHZ,
            VulnClass.OAUTH, VulnClass.XSS, VulnClass.SQLI,
            VulnClass.SSTI, VulnClass.INFO_DISCLOSURE,
            VulnClass.CORS, VulnClass.OPEN_REDIRECT,
        ]

    async def _execute_hunt_cycle(self, target: str, vuln_class: str,
                                   strategy: Dict, mode: str) -> List[Dict]:
        """Execute a single hunt cycle for a specific vuln class."""
        findings = []

        if not self.mcp:
            logger.warning("No MCP client — hunt cycle skipped")
            return findings

        # Phase 1: Run nuclei with vuln-class-specific templates
        if "nuclei" in strategy.get("tools", []):
            tags = ",".join(strategy.get("nuclei_tags", []))
            severity = "low,medium,high,critical" if mode == "aggressive" else "medium,high,critical"
            result = await self.mcp.execute(
                tool_name="nuclei_scan",
                params={
                    "target": target,
                    "severity": severity,
                    "tags": tags,
                },
            )
            if result.get("success") and result.get("output"):
                parsed = self._parse_nuclei_output(result["output"])
                for f in parsed:
                    f["hunt_class"] = vuln_class
                    f["hunt_source"] = "nuclei"
                findings.extend(parsed)

        # Phase 2: Run fuzzing if strategy has payloads
        if "ffuf" in strategy.get("tools", []) and strategy.get("payloads"):
            # Fuzz parameter-bearing endpoints
            params = strategy.get("parameter_targets", [])
            if params:
                for param in params[:5]:  # Limit to avoid abuse
                    result = await self.mcp.execute(
                        tool_name="fuzz_endpoint",
                        params={"target": f"{target}/?{param}=FUZZ"},
                    )
                    if result.get("success") and result.get("output"):
                        for line in result["output"].strip().split("\n"):
                            if line.strip():
                                findings.append({
                                    "name": f"Potential {vuln_class.upper()} via {param}",
                                    "type": vuln_class,
                                    "matched_at": line.strip(),
                                    "severity": "medium",
                                    "hunt_source": "ffuf",
                                    "confidence_score": 0.5,
                                })

        # Phase 3: Path discovery for info disclosure
        if strategy.get("paths"):
            for path in strategy["paths"][:10]:
                result = await self.mcp.execute(
                    tool_name="http_probe",
                    params={"target": f"{target}{path}"},
                )
                if result.get("success") and result.get("output"):
                    output = result["output"].strip()
                    if output and "200" in output:
                        findings.append({
                            "name": f"Exposed path: {path}",
                            "type": "info_disclosure",
                            "matched_at": f"{target}{path}",
                            "severity": "low",
                            "hunt_source": "httpx",
                            "evidence": output[:500],
                            "confidence_score": 0.7,
                        })

        return findings

    def _parse_nuclei_output(self, output: str) -> List[Dict]:
        """Parse nuclei JSONL output into findings."""
        import json
        findings = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "name": data.get("info", {}).get("name", data.get("template-id", "")),
                    "type": data.get("type", "nuclei"),
                    "severity": data.get("info", {}).get("severity", "info"),
                    "matched_at": data.get("matched-at", data.get("host", "")),
                    "template_id": data.get("template-id", ""),
                    "evidence": data.get("extracted-results", data.get("matcher-name", "")),
                    "confidence_score": 0.85,
                    "reproduction_steps": f"nuclei -u {data.get('host', '')} -t {data.get('template-id', '')}",
                })
            except (json.JSONDecodeError, KeyError):
                if "[" in line and "]" in line:
                    findings.append({
                        "name": line, "type": "nuclei_raw",
                        "severity": "info", "matched_at": line,
                        "confidence_score": 0.5,
                    })
        return findings

    def get_session(self, session_id: str) -> Optional[HuntSession]:
        return self._active_sessions.get(session_id)

    def get_hunt_history(self) -> List[Dict]:
        return list(self._hunt_history)

    def get_strategy(self, vuln_class: str) -> Optional[Dict]:
        return HUNT_STRATEGIES.get(vuln_class)

    def list_strategies(self) -> Dict[str, str]:
        return {k: v["name"] for k, v in HUNT_STRATEGIES.items()}
