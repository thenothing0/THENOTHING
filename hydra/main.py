"""
╔══════════════════════════════════════════════════════════════╗
║  THENOTHING v7.1 — Cognitive Autonomous Red Team Platform   ║
║  Kali Native · WAF Bypass · GitHub Intel · Smart Strategy   ║
║  Usage: python -m hydra.main -t example.com                 ║
║         python -m hydra.main -t example.com -w cognitive_auto║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Config + infra (always available) ────────
from hydra.config import get_config, LOGS_DIR, RESULTS_DIR

# ── Core subsystems (gracefully imported) ────
from hydra.mcp.tool_server import MCPToolServer
from hydra.mcp.client import MCPClient
from hydra.memory.bus import MemoryBus

# ═══════════════════════════════════════════════
#  CLI — argparse (no extra deps required)
# ═══════════════════════════════════════════════

BANNER = r"""
   _____ _   _ _____ _   _  ___ _____ _   _ ___ _   _  ____
  |_   _| | | | ____| \ | |/ _ \_   _| | | |_ _| \ | |/ ___|
    | | | |_| |  _| |  \| | | | || | | |_| || ||  \| | |  _
    | | |  _  | |___| |\  | |_| || | |  _  || || |\  | |_| |
    |_| |_| |_|_____|_| \_|\___/ |_| |_| |_|___|_| \_|\____|

   Cognitive Autonomous Red Team Platform                     v7.1
   Kali Native · WAF Bypass · GitHub Intel · Smart Strategy · Swarm
"""

AVAILABLE_WORKFLOWS = [
    "quick_recon", "full_bounty", "api_only",
    "osint_recon", "full_auto",
    "web3_audit", "blackbox", "code_review",
    "cognitive_auto", "bounty_hunt",
]

logger = logging.getLogger("hydra")


# ═══════════════════════════════════════════════
#  Rich console helpers (pure stdlib fallback)
# ═══════════════════════════════════════════════

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.logging import RichHandler
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

_con = None

def console():
    global _con
    if _con is None:
        _con = Console() if HAS_RICH else None
    return _con

def rprint(msg: str, **kw):
    c = console()
    if c:
        c.print(msg, **kw)
    else:
        print(msg)


# ═══════════════════════════════════════════════
#  Logging setup
# ═══════════════════════════════════════════════

def setup_logging(verbose: bool = False):
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO

    handlers: list = [logging.FileHandler(str(LOGS_DIR / "hydra.log"), encoding="utf-8")]

    if HAS_RICH:
        handlers.insert(0, RichHandler(
            level=level, show_path=False, show_time=True,
            markup=True, rich_tracebacks=True,
        ))
    else:
        handlers.insert(0, logging.StreamHandler(sys.stdout))

    logging.basicConfig(
        level=level,
        format="%(message)s" if HAS_RICH else "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )
    for lib in ["urllib3", "aiohttp", "asyncio", "httpx", "httpcore"]:
        logging.getLogger(lib).setLevel(logging.WARNING)


# ═══════════════════════════════════════════════
#  CLI parser
# ═══════════════════════════════════════════════

def build_parser():
    import argparse
    p = argparse.ArgumentParser(
        prog="hydra",
        description="THENOTHING v7.1 — Cognitive Autonomous Red Team Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m hydra.main -t example.com\n"
            "  python -m hydra.main -t example.com -w quick_recon\n"
            "  python -m hydra.main -t api.example.com -w api_only\n"
            "  python -m hydra.main --check-tools\n"
            "  python -m hydra.main --list-workflows\n"
        ),
    )
    p.add_argument("-t", "--target", help="Target domain or URL")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("-w", "--workflow", default="quick_recon",
                   choices=AVAILABLE_WORKFLOWS,
                   help="Workflow template (default: quick_recon)")
    p.add_argument("--list-workflows", action="store_true", help="Show available workflows")
    p.add_argument("--check-tools", action="store_true", help="Check tool availability")
    p.add_argument("--install-tools", action="store_true", help="Auto-install missing tools")
    p.add_argument("--no-ai", action="store_true", help="Disable AI features (tool-only mode)")
    p.add_argument("--output-dir", default="output", help="Output directory")
    p.add_argument("--scope-url", type=str, help="HackerOne/Bugcrowd scope URL")
    p.add_argument("--timeout", type=int, default=120, help="Per-tool timeout in seconds")
    p.add_argument("--budget", type=float, default=5.0, help="Per-scan AI budget (USD)")
    return p


# ═══════════════════════════════════════════════
#  Core engine — the part that actually runs tools
# ═══════════════════════════════════════════════

class HydraEngine:
    """
    THENOTHING v7.1 — Cognitive Autonomous Red Team Engine.

    Integrates:
      v4: OSINT, fingerprinting, intelligence packs, heuristic reasoning,
          hallucination defense, scope enforcement, MCP tool execution
      v5: Cognitive reasoning loop, environment simulation, causal AI,
          stealth/OPSEC, deception detection, recon expansion, temporal
          intelligence, human emulation, continuous learning, red-team
          critic, collaborative swarm intelligence
      v6: World model, adversarial debate, payload engine
      v7: Autonomous bounty hunter, researcher profiles, audit trail,
          ethical guardrails
      v7.1: Kali Linux tool integration, advanced 403 WAF bypass engine,
            GitHub intelligence engine, smart research strategy

    Works NOW with zero external services (no Redis, no ChromaDB needed).
    """

    def __init__(self, target: str, workflow: str = "quick_recon",
                 output_dir: str = "output", timeout: int = 120,
                 scope_url: str = ""):
        self.target = target
        self.workflow_name = workflow
        self.output_dir = Path(output_dir) / self._safe_dir(target)
        self.timeout = timeout
        self.scope_url = scope_url
        self.tool_server: Optional[MCPToolServer] = None
        self.mcp: Optional[MCPClient] = None
        self.findings: List[Dict[str, Any]] = []
        self.recon_data: Dict[str, Any] = {}
        self._start_time = 0.0
        # v4 subsystems (lazy-loaded)
        self._scope_engine = None
        self._osint_engine = None
        self._fingerprinter = None
        self._pack_registry = None
        self._heuristics = None
        self._hallucination_defense = None
        self._artifact_store = None
        # v5 cognitive subsystems (lazy-loaded)
        self._cognitive_loop = None
        self._simulation_engine = None
        self._causal_engine = None
        self._stealth_engine = None
        self._deception_engine = None
        self._recon_expander = None
        self._temporal_engine = None
        self._human_emulator = None
        self._learning_engine = None
        self._red_team_critic = None
        self._cognitive_graph = None
        self._swarm = None
        # v6 additions
        self._world_model = None
        self._debate_engine = None
        self._payload_engine = None
        # v7 — autonomous cognitive red team
        self._bounty_hunter = None
        self._researcher_profiles = None
        self._audit_trail = None
        self._guardrails = None

    @staticmethod
    def _safe_dir(target: str) -> str:
        return target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")

    # ── Lifecycle ──────────────────────────────

    async def init(self):
        """Initialise MCP tool server and v4 subsystems."""
        self._start_time = time.time()

        # Output dirs (expanded for OSINT + attack graph)
        for sub in ["recon", "osint", "scans", "reports", "evidence",
                    "logs", "attack_graph", "memory", "raw"]:
            (self.output_dir / sub).mkdir(parents=True, exist_ok=True)

        # Artifact store
        try:
            from hydra.output import ArtifactStore
            self._artifact_store = ArtifactStore(str(self.output_dir.parent))
            self._artifact_store.initialize_target(self.target)
        except Exception:
            pass

        # Tool server
        self.tool_server = MCPToolServer()
        await self.tool_server.initialize()
        if self._artifact_store:
            self.tool_server.set_artifact_store(self._artifact_store)
        self.mcp = MCPClient(tool_server=self.tool_server)

        # Scope enforcement
        if self.scope_url:
            await self._init_scope()

        # v4 subsystems (lightweight, no external deps)
        self._init_v4_subsystems()

        # v5 cognitive subsystems
        self._init_v5_subsystems()

        logger.info("[bold green]✅ THENOTHING v7.1 engine ready[/bold green]")

    async def _init_scope(self):
        """Initialize scope from program URL."""
        try:
            from hydra.scope import ScopePolicyEngine
            self._scope_engine = ScopePolicyEngine()
            scope = await self._scope_engine.load_from_url(self.scope_url)
            self.tool_server.set_scope_engine(self._scope_engine)
            logger.info(f"[bold]🔒 Scope loaded: {scope.program_name} "
                        f"({len(scope.in_scope)} in-scope)[/bold]")
        except Exception as e:
            logger.warning(f"Scope loading failed: {e}")

    def _init_v4_subsystems(self):
        """Initialize v4 intelligence subsystems."""
        try:
            from hydra.fingerprint import TechnologyFingerprinter
            self._fingerprinter = TechnologyFingerprinter()
        except Exception:
            pass
        try:
            from hydra.packs import PackRegistry
            self._pack_registry = PackRegistry()
        except Exception:
            pass
        try:
            from hydra.heuristics import HeuristicReasoningEngine
            self._heuristics = HeuristicReasoningEngine()
        except Exception:
            pass
        try:
            from hydra.hallucination import HallucinationDefense
            self._hallucination_defense = HallucinationDefense()
        except Exception:
            pass
        try:
            from hydra.osint import OSINTIntelligenceEngine
            config = get_config()
            self._osint_engine = OSINTIntelligenceEngine(api_keys=config.api_keys)
        except Exception:
            pass

    def _init_v5_subsystems(self):
        """Initialize v5 cognitive intelligence subsystems."""
        try:
            from hydra.cognitive import CognitiveLoop
            self._cognitive_loop = CognitiveLoop(self.target)
        except Exception:
            pass
        try:
            from hydra.simulation import EnvironmentSimulator
            self._simulation_engine = EnvironmentSimulator()
        except Exception:
            pass
        try:
            from hydra.causal import CausalReasoningEngine
            self._causal_engine = CausalReasoningEngine()
        except Exception:
            pass
        try:
            from hydra.stealth import StealthEngine
            self._stealth_engine = StealthEngine()
        except Exception:
            pass
        try:
            from hydra.deception import DeceptionDetectionEngine
            self._deception_engine = DeceptionDetectionEngine()
        except Exception:
            pass
        try:
            from hydra.recon_expansion import ReconExpansionEngine
            self._recon_expander = ReconExpansionEngine()
        except Exception:
            pass
        try:
            from hydra.temporal import TemporalIntelligenceEngine
            self._temporal_engine = TemporalIntelligenceEngine()
        except Exception:
            pass
        try:
            from hydra.human_emulation import HumanEmulationEngine
            self._human_emulator = HumanEmulationEngine()
        except Exception:
            pass
        try:
            from hydra.continuous_learning import ContinuousLearningEngine
            self._learning_engine = ContinuousLearningEngine(
                persist_dir=str(self.output_dir / "memory"))
        except Exception:
            pass
        try:
            from hydra.red_team_critic import RedTeamCriticAgent
            self._red_team_critic = RedTeamCriticAgent()
        except Exception:
            pass
        try:
            from hydra.cognitive_graph import CognitiveGraph
            self._cognitive_graph = CognitiveGraph()
        except Exception:
            pass
        try:
            from hydra.swarm_intelligence import CollaborativeSwarm
            self._swarm = CollaborativeSwarm()
        except Exception:
            pass
        try:
            from hydra.world_model import WorldModelEngine
            self._world_model = WorldModelEngine()
        except Exception:
            pass
        try:
            from hydra.debate import DebateEngine
            self._debate_engine = DebateEngine()
        except Exception:
            pass
        try:
            from hydra.payload_engine import PayloadEngine
            self._payload_engine = PayloadEngine()
        except Exception:
            pass

        # v7 subsystems — autonomous red team layer
        try:
            from hydra.bounty_hunter import BountyHunterEngine
            config = get_config()
            self._bounty_hunter = BountyHunterEngine({
                "hackerone_token": config.scope.hackerone_token,
            })
        except Exception:
            pass
        try:
            from hydra.researcher_profiles import ResearcherProfileEngine
            self._researcher_profiles = ResearcherProfileEngine()
        except Exception:
            pass
        try:
            from hydra.audit import AuditTrail
            self._audit_trail = AuditTrail(
                persist_dir=str(self.output_dir / "audit"))
        except Exception:
            pass
        try:
            from hydra.guardrails import GuardrailsEngine
            self._guardrails = GuardrailsEngine()
        except Exception:
            pass

        # Wire cognitive loop to subsystems
        if self._cognitive_loop:
            self._cognitive_loop.attach(
                simulation_engine=self._simulation_engine,
                causal_engine=self._causal_engine,
                stealth_engine=self._stealth_engine,
                learning_engine=self._learning_engine,
                recon_expander=self._recon_expander,
                world_model=self._world_model,
                debate_engine=self._debate_engine,
            )

        all_subsystems = [
            self._cognitive_loop, self._simulation_engine,
            self._causal_engine, self._stealth_engine,
            self._deception_engine, self._recon_expander,
            self._temporal_engine, self._human_emulator,
            self._learning_engine, self._red_team_critic,
            self._cognitive_graph, self._swarm,
            self._world_model, self._debate_engine, self._payload_engine,
            self._bounty_hunter, self._researcher_profiles,
            self._audit_trail, self._guardrails,
        ]
        v7_active = sum(1 for s in all_subsystems if s is not None)
        logger.info(f"🧠 v7 cognitive subsystems active: {v7_active}/19")

    async def run(self) -> Dict[str, Any]:
        """Run the selected workflow and return a summary."""
        logger.info(f"[bold cyan]🎯 Target:[/] {self.target}")
        logger.info(f"[bold cyan]📋 Workflow:[/] {self.workflow_name}")

        # Dynamic workflow dispatch
        runner = getattr(self, f"_wf_{self.workflow_name}", None)
        if runner is None:
            logger.error(f"Unknown workflow: {self.workflow_name}")
            return {"error": f"Unknown workflow: {self.workflow_name}"}

        await runner()

        elapsed = round(time.time() - self._start_time, 1)
        summary = {
            "target": self.target,
            "workflow": self.workflow_name,
            "elapsed_s": elapsed,
            "recon": {k: len(v) if isinstance(v, list) else v
                      for k, v in self.recon_data.items()},
            "findings_count": len(self.findings),
            "findings": self.findings,
            "output_dir": str(self.output_dir),
        }
        self._save_json("reports/summary.json", summary)
        return summary

    # ═══════════════════════════════════════════
    #  WORKFLOW: quick_recon
    # ═══════════════════════════════════════════

    async def _wf_quick_recon(self):
        """Fast recon: subdomains → probing → tech detect → nuclei quick."""
        logger.info("[bold]── Phase 1/4: Subdomain Enumeration ──[/bold]")
        subs = await self._run_tool("subfinder", {"target": self.target})
        self.recon_data["subdomains"] = self._lines(subs)
        self._save_lines("recon/subdomains.txt", self.recon_data["subdomains"])
        logger.info(f"  Found [green]{len(self.recon_data['subdomains'])}[/] subdomains")

        logger.info("[bold]── Phase 2/4: HTTP Probing ──[/bold]")
        targets_for_probe = "\n".join(self.recon_data["subdomains"]) or self.target
        probe = await self._run_tool("httpx", {"target": self.target}, stdin=targets_for_probe)
        self.recon_data["live_hosts"] = self._lines(probe)
        self._save_lines("recon/live_hosts.txt", self.recon_data["live_hosts"])
        logger.info(f"  Found [green]{len(self.recon_data['live_hosts'])}[/] live hosts")

        logger.info("[bold]── Phase 3/4: Technology Detection ──[/bold]")
        tech = await self._run_tool("whatweb", {"target": self.target})
        self.recon_data["tech"] = tech.get("output", "")[:2000]
        self._save_text("recon/tech.txt", self.recon_data["tech"])

        logger.info("[bold]── Phase 4/4: Vulnerability Scan (nuclei) ──[/bold]")
        scan = await self._run_tool("nuclei", {
            "target": self.target,
            "severity": "medium,high,critical",
        })
        self.findings = self._parse_nuclei(scan.get("output", ""))
        self._save_json("scans/nuclei_results.json", self.findings)
        logger.info(f"  Found [{'red' if self.findings else 'green'}]{len(self.findings)}[/] vulnerabilities")

    # ═══════════════════════════════════════════
    #  WORKFLOW: full_bounty
    # ═══════════════════════════════════════════

    async def _wf_full_bounty(self):
        """Complete assessment: recon → crawl → fuzz → nuclei full → report."""
        # Phase 1-3: same as quick_recon
        await self._wf_quick_recon()

        logger.info("[bold]── Phase 5: URL Crawling (katana) ──[/bold]")
        crawl = await self._run_tool("katana", {"target": self.target})
        self.recon_data["urls"] = self._lines(crawl)
        self._save_lines("recon/urls.txt", self.recon_data["urls"])
        logger.info(f"  Crawled [green]{len(self.recon_data['urls'])}[/] URLs")

        logger.info("[bold]── Phase 6: Directory Brute ──[/bold]")
        dirs = await self._run_tool("dirsearch", {"target": self.target})
        self.recon_data["dirs"] = dirs.get("output", "")[:2000]

        logger.info("[bold]── Phase 7: Full Nuclei Scan (all severities) ──[/bold]")
        full_scan = await self._run_tool("nuclei", {
            "target": self.target,
            "severity": "low,medium,high,critical",
        })
        extra = self._parse_nuclei(full_scan.get("output", ""))
        seen = {f.get("template_id") for f in self.findings}
        for f in extra:
            if f.get("template_id") not in seen:
                self.findings.append(f)
        self._save_json("scans/nuclei_full.json", self.findings)
        logger.info(f"  Total findings: [red]{len(self.findings)}[/]")

    # ═══════════════════════════════════════════
    #  WORKFLOW: api_only
    # ═══════════════════════════════════════════

    async def _wf_api_only(self):
        """API-focused: probe → nuclei API tags → fuzz."""
        logger.info("[bold]── Phase 1: HTTP Probing ──[/bold]")
        probe = await self._run_tool("httpx", {"target": self.target})
        self.recon_data["live_hosts"] = self._lines(probe)

        logger.info("[bold]── Phase 2: API Vulnerability Scan ──[/bold]")
        scan = await self._run_tool("nuclei", {
            "target": self.target,
            "severity": "medium,high,critical",
            "tags": "api,graphql,jwt,oauth,idor",
        })
        self.findings = self._parse_nuclei(scan.get("output", ""))
        self._save_json("scans/api_scan.json", self.findings)
        logger.info(f"  Found [red]{len(self.findings)}[/] API vulnerabilities")

    # ═══════════════════════════════════════════
    #  WORKFLOW: blackbox
    # ═══════════════════════════════════════════

    async def _wf_blackbox(self):
        """Black-box: aggressive recon → full scan → fuzz."""
        await self._wf_full_bounty()  # same pipeline, more aggressive

    # ═══════════════════════════════════════════
    #  WORKFLOW: osint_recon (NEW v4)
    # ═══════════════════════════════════════════

    async def _wf_osint_recon(self):
        """OSINT-first: passive intel → fingerprint → targeted scan."""
        # Phase 1: OSINT Intelligence
        logger.info("[bold]── Phase 1/4: OSINT Intelligence ──[/bold]")
        if self._osint_engine:
            try:
                report = await self._osint_engine.run_full_osint(self.target)
                self.recon_data["osint_assets"] = [a.asset for a in report.assets[:200]]
                self.recon_data["osint_findings"] = len(report.findings)
                self._save_json("osint/osint_report.json", report.to_dict())
                self._save_json("osint/attack_surface.json", report.attack_surface)
                logger.info(f"  OSINT: [green]{len(report.assets)}[/] assets, "
                            f"[green]{len(report.findings)}[/] findings")
                # Feed subdomains from OSINT into recon data
                osint_subs = [a.asset for a in report.assets if a.asset_type == "domain"]
                self.recon_data["subdomains"] = osint_subs
                self._save_lines("recon/subdomains_osint.txt", osint_subs)
            except Exception as e:
                logger.warning(f"  OSINT failed: {e}")
        else:
            logger.info("  [dim]OSINT engine not available — skipping[/dim]")

        # Phase 2: Technology Fingerprinting
        logger.info("[bold]── Phase 2/4: Technology Fingerprinting ──[/bold]")
        if self._fingerprinter:
            try:
                fp = await self._fingerprinter.fingerprint(self.target)
                self.recon_data["technologies"] = [
                    {"name": t.name, "category": t.category, "confidence": t.confidence}
                    for t in fp.technologies
                ]
                self._save_json("recon/fingerprint.json", {
                    "server": fp.server, "framework": fp.framework,
                    "cms": fp.cms, "cdn": fp.cdn, "waf": fp.waf_detected,
                    "cloud": fp.cloud_provider, "technologies": self.recon_data["technologies"],
                })
                # Activate intelligence packs
                if self._pack_registry:
                    triggers = fp.get_intelligence_pack_triggers()
                    activated = self._pack_registry.activate_packs(triggers)
                    self.recon_data["packs_activated"] = [p.name for p in activated]
                    logger.info(f"  Packs activated: [cyan]{', '.join(self.recon_data.get('packs_activated', []))}[/]")
                # Feed technologies to heuristics
                if self._heuristics:
                    for t in fp.technologies:
                        self._heuristics.add_technology(t.name)
                logger.info(f"  Detected: [green]{len(fp.technologies)}[/] technologies")
            except Exception as e:
                logger.warning(f"  Fingerprinting failed: {e}")

        # Phase 3: Tool-based recon
        logger.info("[bold]── Phase 3/4: Subdomain + HTTP Probing ──[/bold]")
        subs = await self._run_tool("subfinder", {"target": self.target})
        tool_subs = self._lines(subs)
        # Merge with OSINT subdomains
        all_subs = list(set(self.recon_data.get("subdomains", []) + tool_subs))
        self.recon_data["subdomains"] = all_subs
        self._save_lines("recon/subdomains.txt", all_subs)
        logger.info(f"  Total subdomains: [green]{len(all_subs)}[/]")

        probe = await self._run_tool("httpx", {"target": self.target},
                                     stdin="\n".join(all_subs) if all_subs else None)
        self.recon_data["live_hosts"] = self._lines(probe)
        self._save_lines("recon/live_hosts.txt", self.recon_data["live_hosts"])

        # Phase 4: Heuristic-guided vulnerability scan
        logger.info("[bold]── Phase 4/4: Heuristic-Guided Scan ──[/bold]")
        nuclei_tags = ""
        if self._pack_registry:
            nuclei_tags = ",".join(self._pack_registry.get_all_nuclei_tags())
        scan_params = {"target": self.target, "severity": "medium,high,critical"}
        if nuclei_tags:
            scan_params["tags"] = nuclei_tags
        scan = await self._run_tool("nuclei", scan_params)
        self.findings = self._parse_nuclei(scan.get("output", ""))
        # Hallucination defense on findings
        if self._hallucination_defense and self.findings:
            self.findings = self._hallucination_defense.filter_verified_findings(
                self.findings, min_confidence=0.3)
        self._save_json("scans/nuclei_results.json", self.findings)
        logger.info(f"  Findings: [{'red' if self.findings else 'green'}]{len(self.findings)}[/]")

    # ═══════════════════════════════════════════
    #  WORKFLOW: full_auto (NEW v4)
    # ═══════════════════════════════════════════

    async def _wf_full_auto(self):
        """Full autonomous: OSINT → fingerprint → heuristic scan → crawl → fuzz → validate."""
        await self._wf_osint_recon()

        logger.info("[bold]── Phase 5: URL Crawling ──[/bold]")
        crawl = await self._run_tool("katana", {"target": self.target})
        self.recon_data["urls"] = self._lines(crawl)
        self._save_lines("recon/urls.txt", self.recon_data["urls"])
        logger.info(f"  Crawled [green]{len(self.recon_data['urls'])}[/] URLs")

        logger.info("[bold]── Phase 6: Full Nuclei Scan ──[/bold]")
        full_scan = await self._run_tool("nuclei", {
            "target": self.target, "severity": "low,medium,high,critical",
        })
        extra = self._parse_nuclei(full_scan.get("output", ""))
        seen = {f.get("template_id") for f in self.findings}
        for f in extra:
            if f.get("template_id") not in seen:
                self.findings.append(f)
        self._save_json("scans/nuclei_full.json", self.findings)

        # Heuristic summary
        if self._heuristics:
            for f in self.findings:
                self._heuristics.add_finding(f)
            profile = self._heuristics.get_scan_profile()
            self._save_json("reports/heuristic_profile.json", profile)

        logger.info(f"  Total findings: [red]{len(self.findings)}[/]")

    # ═══════════════════════════════════════════
    #  WORKFLOW: cognitive_auto (v6 — THE FLAGSHIP)
    # ═══════════════════════════════════════════

    async def _wf_cognitive_auto(self):
        """
        Full autonomous cognitive pipeline.

        Observe → Understand → Reason → Simulate → Plan → Execute → Validate → Learn → Replan

        Wires all 12 v5 subsystems into a unified autonomous red team:
          - Cognitive Loop (brain)
          - Simulation Engine (pre-execution forecasting)
          - Causal Reasoning (counterfactual analysis)
          - Stealth Engine (OPSEC-aware execution)
          - Deception Detection (honeypot filtering)
          - Recon Expansion (recursive asset inference)
          - Temporal Intelligence (infrastructure history)
          - Continuous Learning (self-improvement)
          - Red Team Critic (adversarial self-critique)
          - Cognitive Graph (attack surface memory)
          - Collaborative Swarm (multi-agent coordination)
          - Debate System (multi-agent adversarial validation)
        """
        from hydra.cognitive import CognitivePhase, Observation, CognitiveLoop

        if not self._cognitive_loop:
            logger.warning("Cognitive loop not available — falling back to full_auto")
            await self._wf_full_auto()
            return

        # Load v7 master system prompt
        try:
            from hydra.prompts import load_master_prompt
            master_prompt = load_master_prompt()
            self._save_text("prompts/active_system_prompt.md", master_prompt)
            logger.info("🧠 v7 Master Prompt loaded — Cognitive Red Team identity active")
        except Exception:
            pass

        cognitive = self._cognitive_loop

        # ── v7: Researcher Profile + Guardrails + Audit Setup ────

        # Auto-select researcher profile from target context
        if self._researcher_profiles:
            tech_hints = []
            if self._fingerprinter:
                try:
                    tech_hints = self._fingerprinter.get_known_techs(self.target)
                except Exception:
                    pass
            profile = self._researcher_profiles.select_profile(
                tech_stack=tech_hints,
            )
            # Apply profile's stealth mode
            if self._stealth_engine:
                from hydra.stealth import StealthMode
                mode_map = {
                    "ghost": StealthMode.GHOST, "stealth": StealthMode.STEALTH,
                    "cautious": StealthMode.CAUTIOUS, "normal": StealthMode.NORMAL,
                    "aggressive": StealthMode.AGGRESSIVE,
                }
                self._stealth_engine.set_mode(
                    mode_map.get(profile.stealth_mode, StealthMode.NORMAL)
                )

        # Initialize guardrails for target scope
        if self._guardrails:
            from hydra.guardrails import ActionType
            target_check = self._guardrails.check_target(self.target)
            if not target_check.allowed:
                logger.error(f"🚫 Target blocked by guardrails: {target_check.reason}")
                return

        # Record session start in audit trail
        if self._audit_trail:
            from hydra.audit import DecisionCategory
            self._audit_trail.record(
                category=DecisionCategory.EXECUTION,
                action=f"cognitive_auto session started on {self.target}",
                rationale="Autonomous cognitive pipeline initiated",
                chain_of_thought=[
                    f"Target: {self.target}",
                    f"Profile: {self._researcher_profiles.active.name if self._researcher_profiles else 'balanced'}",
                    f"Stealth: {self._stealth_engine.profile.mode.value if self._stealth_engine else 'normal'}",
                ],
                confidence=0.9,
            )

        # ── Wire MCP execution into the cognitive loop ──────────

        engine_ref = self  # capture for closures

        async def observe_phase():
            """OBSERVE: Run passive recon tools and OSINT to gather raw data."""
            logger.info("[bold magenta]🔭 OBSERVE — Gathering raw intelligence[/bold magenta]")

            # 1. Subdomain enumeration
            subs_result = await engine_ref._run_tool("subfinder", {"target": engine_ref.target})
            subs = engine_ref._lines(subs_result)
            engine_ref.recon_data["subdomains"] = subs
            engine_ref._save_lines("recon/subdomains.txt", subs)
            for sub in subs:
                cognitive.add_observation(Observation(
                    source="subfinder", observation_type="asset",
                    data={"domain": sub, "asset_type": "subdomain"},
                    confidence=0.95, raw_evidence=sub,
                ))

            # 2. HTTP probing
            probe = await engine_ref._run_tool("httpx", {"target": engine_ref.target},
                                                stdin="\n".join(subs) if subs else None)
            live = engine_ref._lines(probe)
            engine_ref.recon_data["live_hosts"] = live
            engine_ref._save_lines("recon/live_hosts.txt", live)
            for host in live:
                cognitive.add_observation(Observation(
                    source="httpx", observation_type="endpoint",
                    data={"url": host, "live": True},
                    confidence=0.99, raw_evidence=host,
                ))

            # 3. OSINT intelligence (if available)
            if engine_ref._osint_engine:
                try:
                    report = await engine_ref._osint_engine.run_full_osint(engine_ref.target)
                    engine_ref.recon_data["osint_assets"] = [a.asset for a in report.assets[:200]]
                    engine_ref._save_json("osint/osint_report.json", report.to_dict())
                    for asset in report.assets[:100]:
                        cognitive.add_observation(Observation(
                            source="osint", observation_type="asset",
                            data={"domain": asset.asset, "asset_type": asset.asset_type,
                                  "source": asset.source},
                            confidence=asset.confidence,
                        ))
                    for finding in report.findings[:50]:
                        cognitive.add_observation(Observation(
                            source="osint", observation_type="vulnerability",
                            data=finding, confidence=0.6,
                        ))
                    logger.info(f"  OSINT: [green]{len(report.assets)}[/] assets, "
                                f"[green]{len(report.findings)}[/] findings")
                except Exception as e:
                    logger.warning(f"  OSINT: {e}")

            # 4. Technology fingerprinting
            if engine_ref._fingerprinter:
                try:
                    fp = await engine_ref._fingerprinter.fingerprint(engine_ref.target)
                    engine_ref.recon_data["technologies"] = [
                        {"name": t.name, "category": t.category, "confidence": t.confidence}
                        for t in fp.technologies
                    ]
                    engine_ref._save_json("recon/fingerprint.json", {
                        "server": fp.server, "framework": fp.framework,
                        "cms": fp.cms, "cdn": fp.cdn, "waf": fp.waf_detected,
                        "technologies": engine_ref.recon_data["technologies"],
                    })
                    for tech in fp.technologies:
                        cognitive.add_observation(Observation(
                            source="fingerprinter", observation_type="technology",
                            data={"name": tech.name, "category": tech.category,
                                  "version": getattr(tech, "version", "")},
                            confidence=tech.confidence,
                        ))
                    # Feed to heuristics
                    if engine_ref._heuristics:
                        for t in fp.technologies:
                            engine_ref._heuristics.add_technology(t.name)
                    # Activate intelligence packs
                    if engine_ref._pack_registry:
                        triggers = fp.get_intelligence_pack_triggers()
                        activated = engine_ref._pack_registry.activate_packs(triggers)
                        logger.info(f"  Packs: [cyan]{', '.join(p.name for p in activated)}[/]")
                except Exception as e:
                    logger.warning(f"  Fingerprint: {e}")

            # 5. Temporal intelligence
            if engine_ref._temporal_engine:
                try:
                    history = await engine_ref._temporal_engine.analyze(engine_ref.target)
                    for record in getattr(history, "changes", [])[:20]:
                        cognitive.add_observation(Observation(
                            source="temporal", observation_type="infrastructure",
                            data={"change": record}, confidence=0.5,
                        ))
                except Exception as e:
                    logger.debug(f"  Temporal: {e}")

            # 6. Deception detection
            if engine_ref._deception_engine:
                try:
                    for host in live[:10]:
                        score = engine_ref._deception_engine.score_target(host)
                        if score and score.get("is_honeypot", False):
                            cognitive.add_observation(Observation(
                                source="deception_detector", observation_type="behavior",
                                data={"host": host, "honeypot": True, "score": score},
                                confidence=score.get("confidence", 0.5),
                            ))
                            logger.info(f"  ⚠️  Honeypot suspected: [yellow]{host}[/yellow]")
                except Exception as e:
                    logger.debug(f"  Deception: {e}")

            logger.info(f"  Observations: [green]{len(cognitive.state.observations)}[/]")

        async def execute_phase():
            """EXECUTE: Run tools based on cognitive decisions with stealth awareness."""
            logger.info("[bold magenta]⚡ EXECUTE — Running tools based on cognitive plan[/bold magenta]")

            # Get stealth profile
            stealth_delay = 0
            if engine_ref._stealth_engine:
                try:
                    profile = engine_ref._stealth_engine.get_profile()
                    stealth_delay = getattr(profile, "inter_request_delay", 0)
                    logger.info(f"  Stealth: mode={getattr(profile, 'mode', 'normal')}, "
                                f"delay={stealth_delay}s")
                except Exception:
                    pass

            # Execute decisions from the plan phase
            for decision in cognitive.state.decisions[-10:]:
                if decision.decision_type == "expand_recon":
                    # Recursive recon expansion
                    if engine_ref._recon_expander:
                        for action in decision.actions[:5]:
                            target = action.get("target", engine_ref.target)
                            logger.info(f"  🔍 Expanding recon: {target}")
                            expansion = await engine_ref._run_tool("subfinder", {"target": target})
                            new_subs = engine_ref._lines(expansion)
                            for sub in new_subs:
                                cognitive.add_observation(Observation(
                                    source="recon_expansion", observation_type="asset",
                                    data={"domain": sub}, confidence=0.8,
                                ))

                elif decision.decision_type in ("investigate", "exploit"):
                    for action in decision.actions:
                        attack_vector = action.get("type", "")
                        theory_id = action.get("theory_id", "")
                        theory = cognitive._theory_index.get(theory_id)

                        if not theory:
                            continue

                        theory.status = "testing"
                        logger.info(f"  🎯 Testing theory: [bold]{theory.title}[/bold]")

                        # Stealth delay
                        if stealth_delay > 0:
                            await asyncio.sleep(stealth_delay)

                        # Run nuclei with attack-vector-specific tags
                        tag_map = {
                            "wordpress_xss": "wordpress,xss",
                            "frontend_secrets": "exposure,tokens,keys",
                            "auth_bypass": "auth-bypass,default-login,jwt",
                            "ssrf_internal": "ssrf",
                            "sqli": "sqli",
                            "xss": "xss",
                            "idor": "idor",
                            "ssti": "ssti",
                        }
                        tags = tag_map.get(attack_vector, "")

                        scan = await engine_ref._run_tool("nuclei", {
                            "target": engine_ref.target,
                            "severity": "medium,high,critical",
                            **({"tags": tags} if tags else {}),
                        })

                        found = engine_ref._parse_nuclei(scan.get("output", ""))
                        if found:
                            theory.status = "confirmed"
                            theory.evidence = [json.dumps(f) for f in found[:5]]
                            engine_ref.findings.extend(found)
                            for f in found:
                                cognitive.add_observation(Observation(
                                    source="nuclei", observation_type="vulnerability",
                                    data=f, confidence=0.8,
                                    raw_evidence=json.dumps(f),
                                ))
                            logger.info(f"  ✅ Theory CONFIRMED: [red]{theory.title}[/red] "
                                        f"({len(found)} findings)")
                        else:
                            # Not conclusive — may need deeper testing
                            theory.status = "proposed"  # Keep for next cycle
                            theory.confidence *= 0.7  # Decay confidence

            # Deduplicate findings
            seen_ids = set()
            unique = []
            for f in engine_ref.findings:
                fid = f.get("template_id", f.get("name", str(f)))
                if fid not in seen_ids:
                    seen_ids.add(fid)
                    unique.append(f)
            engine_ref.findings = unique
            engine_ref._save_json("scans/cognitive_findings.json", engine_ref.findings)

        async def validate_phase():
            """VALIDATE: Adversarial debate + red team critique on findings."""
            logger.info("[bold magenta]🔬 VALIDATE — Adversarial review of findings[/bold magenta]")

            validated_findings = list(engine_ref.findings)

            # 1. Hallucination defense
            if engine_ref._hallucination_defense and validated_findings:
                try:
                    validated_findings = engine_ref._hallucination_defense.filter_verified_findings(
                        validated_findings, min_confidence=0.3)
                    logger.info(f"  Hallucination filter: {len(engine_ref.findings)} → "
                                f"{len(validated_findings)}")
                except Exception as e:
                    logger.debug(f"  Hallucination defense: {e}")

            # 2. Red team critic review
            if engine_ref._red_team_critic and validated_findings:
                try:
                    critique = engine_ref._red_team_critic.critique_findings(validated_findings)
                    if hasattr(critique, "approved_findings"):
                        validated_findings = critique.approved_findings
                    engine_ref._save_json("reports/red_team_critique.json",
                                          getattr(critique, "to_dict", lambda: {})())
                    logger.info(f"  Red team: {len(validated_findings)} findings approved")
                except Exception as e:
                    logger.debug(f"  Red team critic: {e}")

            engine_ref.findings = validated_findings

            # 3. Update theory statuses based on validation
            confirmed_templates = {f.get("template_id") for f in validated_findings}
            for theory in cognitive.state.theories:
                if theory.status == "confirmed":
                    # Check if evidence survived validation
                    if not any(t in confirmed_templates for t in
                              [e.get("template_id", "") for e in
                               (json.loads(ev) for ev in theory.evidence
                                if ev.startswith("{"))]):
                        theory.status = "refuted"
                        theory.confidence *= 0.3

        async def learn_phase():
            """LEARN: Record outcomes and update knowledge."""
            logger.info("[bold magenta]📚 LEARN — Updating knowledge from outcomes[/bold magenta]")

            # Record to continuous learning engine
            if engine_ref._learning_engine:
                try:
                    for theory in cognitive.state.theories:
                        if theory.status in ("confirmed", "refuted"):
                            engine_ref._learning_engine.record_outcome({
                                "theory": theory.title,
                                "vector": theory.attack_vector,
                                "outcome": theory.status,
                                "target": engine_ref.target,
                                "confidence": theory.confidence,
                                "timestamp": time.time(),
                            })
                    engine_ref._learning_engine.persist()
                    logger.info(f"  Recorded {len(cognitive.state.learnings)} learnings")
                except Exception as e:
                    logger.debug(f"  Learning: {e}")

            # Update cognitive graph
            if engine_ref._cognitive_graph:
                try:
                    # Add all observations as graph nodes
                    for obs in cognitive.state.observations:
                        engine_ref._cognitive_graph.add_entity(
                            entity_type=obs.observation_type,
                            entity_id=obs.id,
                            properties=obs.data,
                        )
                    # Add confirmed theories as attack paths
                    for theory in cognitive.state.theories:
                        if theory.status == "confirmed":
                            engine_ref._cognitive_graph.add_attack_path(
                                name=theory.title,
                                steps=theory.attack_steps,
                                confidence=theory.confidence,
                            )
                    engine_ref._save_json("attack_graph/cognitive_graph.json",
                                          engine_ref._cognitive_graph.to_dict())
                    logger.info("  Cognitive graph updated")
                except Exception as e:
                    logger.debug(f"  Cognitive graph: {e}")

        # ── Register phase handlers on the cognitive loop ──────

        cognitive.register_phase_handler(CognitivePhase.OBSERVE, observe_phase)
        cognitive.register_phase_handler(CognitivePhase.EXECUTE, execute_phase)
        cognitive.register_phase_handler(CognitivePhase.VALIDATE, validate_phase)
        cognitive.register_phase_handler(CognitivePhase.LEARN, learn_phase)

        # ── Run the cognitive loop ──────────────────────────────

        logger.info("[bold green]🧠 Starting Cognitive Autonomous Pipeline[/bold green]")
        logger.info("  Loop: Observe → Understand → Reason → Simulate → Plan → "
                     "Execute → Validate → Learn → Replan")

        state = await cognitive.run(max_cycles=10)

        # ── Post-loop: Exploit Chain Building ───────────────────

        if self.findings:
            try:
                from hydra.chains import ChainBuilder
                chain_builder = ChainBuilder()
                chains = chain_builder.build_chains(self.findings, self.target)
                if chains:
                    self._save_json("reports/exploit_chains.json",
                                    [c.to_dict() for c in chains])
                    chain_md = chain_builder.export_chains(fmt="markdown")
                    self._save_text("reports/exploit_chains.md", chain_md)
                    logger.info(f"  ⛓️ Built [bold]{len(chains)}[/bold] exploit chains")
                    for c in chains[:3]:
                        logger.info(f"    [{c.overall_severity.upper():8s}] "
                                    f"{' → '.join(n.label for n in c.nodes)}")
            except Exception as e:
                logger.debug(f"  Chain builder: {e}")

        # ── Post-loop: Targeted Hunt Cycles ─────────────────────

        if self.mcp and self.findings:
            try:
                from hydra.hunt import HuntEngine
                hunt = HuntEngine(mcp_client=self.mcp,
                                  scope_engine=self._scope_engine,
                                  artifact_store=self._artifact_store)
                # Hunt vuln classes most likely to succeed based on confirmed theories
                confirmed_vectors = {t.attack_vector for t in cognitive.state.theories
                                     if t.status == "confirmed"}
                for vc in list(confirmed_vectors)[:3]:
                    session = await hunt.hunt(self.target, vuln_class=vc,
                                              mode="normal", max_cycles=3)
                    if session.total_findings > 0:
                        for cycle in session.cycles:
                            self.findings.extend(cycle.findings)
                        logger.info(f"  🎯 Hunt [{vc}]: {session.total_findings} findings")
            except Exception as e:
                logger.debug(f"  Hunt engine: {e}")

        # ── Final report ────────────────────────────────────────

        cognitive_summary = cognitive.get_summary()
        engine_ref._save_json("reports/cognitive_summary.json", cognitive_summary)

        logger.info(f"\n[bold]🧠 Cognitive Pipeline Complete[/bold]")
        logger.info(f"  Cycles:         {cognitive_summary['cycles']}")
        logger.info(f"  Understanding:  {cognitive_summary['understanding']:.0%}")
        logger.info(f"  Observations:   {cognitive_summary['observations']}")
        logger.info(f"  Beliefs:        {cognitive_summary['beliefs']}")
        logger.info(f"  Theories:       {cognitive_summary['theories']}")
        logger.info(f"  Findings:       [{'red' if self.findings else 'green'}]"
                     f"{len(self.findings)}[/]")

        # ── v7: Post-loop audit + profile outcome ────────────────

        if self._audit_trail:
            from hydra.audit import DecisionCategory
            self._audit_trail.record(
                category=DecisionCategory.LEARNING,
                action="cognitive_auto session completed",
                rationale=f"{len(self.findings)} findings across "
                          f"{cognitive_summary['cycles']} cycles",
                chain_of_thought=[
                    f"Understanding reached: {cognitive_summary['understanding']:.0%}",
                    f"Theories tested: {cognitive_summary['theories']}",
                    f"Findings validated: {len(self.findings)}",
                ],
                confidence=cognitive_summary["understanding"],
            )
            self._audit_trail.persist()
            logger.info(f"  Audit trail:    {self._audit_trail.get_summary()['total_entries']} entries saved")

        if self._researcher_profiles:
            self._researcher_profiles.record_outcome(
                len(self.findings), success=len(self.findings) > 0
            )
            self._save_json("reports/researcher_profile.json",
                            self._researcher_profiles.get_summary())

        if self._guardrails:
            self._save_json("reports/guardrails_summary.json",
                            self._guardrails.get_summary())

    # ═══════════════════════════════════════════
    #  WORKFLOW: bounty_hunt (v7 — AUTONOMOUS TARGET HUNTING)
    # ═══════════════════════════════════════════

    async def _wf_bounty_hunt(self):
        """
        Fully autonomous bounty hunting workflow.

        1. DISCOVER — Crawl bug bounty platforms for programs
        2. SCORE — Evaluate each program with multi-factor scoring
        3. SELECT — Pick high-value targets with portfolio diversity
        4. PROFILE — Select optimal researcher profile per target
        5. HUNT — Launch cognitive_auto campaigns on selected targets
        6. LEARN — Update strengths from campaign outcomes
        """
        if not self._bounty_hunter:
            logger.warning("Bounty hunter not available — falling back to cognitive_auto")
            await self._wf_cognitive_auto()
            return

        # Phase 1: Discover programs
        logger.info("[bold magenta]🔍 Phase 1: Discovering bug bounty programs[/bold magenta]")
        programs = await self._bounty_hunter.discover()

        if not programs:
            logger.warning("No programs discovered — running cognitive_auto on provided target")
            await self._wf_cognitive_auto()
            return

        # Phase 2: Score all programs
        logger.info("[bold magenta]📊 Phase 2: Scoring programs[/bold magenta]")
        scored = self._bounty_hunter.score_all()

        # Phase 3: Select top targets
        logger.info("[bold magenta]🎯 Phase 3: Selecting high-value targets[/bold magenta]")
        targets = self._bounty_hunter.select_targets(top_n=3)

        if not targets:
            logger.warning("No suitable targets — running cognitive_auto on provided target")
            await self._wf_cognitive_auto()
            return

        # Phase 4: Select researcher profile for first target
        if self._researcher_profiles:
            tech_stack = targets[0].tech_stack if targets else []
            profile = self._researcher_profiles.select_profile(
                tech_stack=tech_stack,
                industry=targets[0].industry if targets else "",
            )
            logger.info(f"  🎭 Profile: {profile.name}")

            # Apply profile to stealth engine
            if self._stealth_engine:
                from hydra.stealth import StealthMode
                mode_map = {
                    "ghost": StealthMode.GHOST,
                    "stealth": StealthMode.STEALTH,
                    "cautious": StealthMode.CAUTIOUS,
                    "normal": StealthMode.NORMAL,
                    "aggressive": StealthMode.AGGRESSIVE,
                }
                self._stealth_engine.set_mode(
                    mode_map.get(profile.stealth_mode, StealthMode.NORMAL)
                )

        # Phase 5: Run cognitive_auto on the top target
        best = targets[0]
        logger.info(f"[bold green]🚀 Launching autonomous hunt on: {best.name}[/bold green]")

        # Record in audit trail
        if self._audit_trail:
            from hydra.audit import DecisionCategory, EvidenceItem, EvidenceType
            self._audit_trail.record(
                category=DecisionCategory.TARGET_SELECT,
                action=f"Selected target: {best.name}",
                rationale=f"Score {best.composite_score:.3f} — max bounty ${best.max_bounty:,.0f}",
                chain_of_thought=[
                    f"Discovered {len(programs)} programs across platforms",
                    f"Scored all programs with multi-factor analysis",
                    f"Selected {best.name} as top target (score={best.composite_score:.3f})",
                    f"Researcher profile: {self._researcher_profiles.active.name if self._researcher_profiles else 'balanced'}",
                ],
                confidence=best.composite_score,
            )

        # Check guardrails for each in-scope asset
        if self._guardrails and best.in_scope:
            from hydra.guardrails import ActionType
            self._guardrails.load_from_scope_assets(
                [{"asset": a.asset, "asset_type": a.asset_type.value}
                 for a in best.in_scope],
            )

        # Override target with top in-scope asset
        if best.in_scope:
            primary_asset = best.in_scope[0].asset
            if primary_asset and not primary_asset.startswith("*"):
                self.target = primary_asset
                logger.info(f"  Primary target asset: {self.target}")

        # Create campaign
        campaign = self._bounty_hunter.create_campaign(best)
        campaign.status = "active"
        campaign.started_at = time.time()

        # Run cognitive_auto on the selected target
        await self._wf_cognitive_auto()

        # Update campaign
        campaign.status = "completed"
        campaign.completed_at = time.time()
        campaign.findings_count = len(self.findings)

        # Phase 6: Learn from outcomes
        if self._researcher_profiles:
            self._researcher_profiles.record_outcome(
                len(self.findings), success=len(self.findings) > 0
            )

        # Save bounty hunt summary
        hunt_summary = {
            "programs_discovered": len(programs),
            "target_selected": best.name,
            "target_score": best.composite_score,
            "campaign_id": campaign.id,
            "findings": len(self.findings),
            "profile_used": self._researcher_profiles.active.name if self._researcher_profiles else "balanced",
        }
        self._save_json("reports/bounty_hunt_summary.json", hunt_summary)

        # Persist audit trail
        if self._audit_trail:
            self._audit_trail.persist()

        logger.info(f"\n[bold]🏆 Bounty Hunt Complete[/bold]")
        logger.info(f"  Target:    {best.name}")
        logger.info(f"  Findings:  [{'red' if self.findings else 'green'}]{len(self.findings)}[/]")
        logger.info(f"  Campaign:  {campaign.id}")

    # ═══════════════════════════════════════════
    #  WORKFLOW stubs for web3 / code_review
    # ═══════════════════════════════════════════

    async def _wf_web3_audit(self):
        logger.info("[bold yellow]Web3 audit requires a .sol file — not yet integrated in CLI.[/]")

    async def _wf_code_review(self):
        logger.info("[bold yellow]Code review workflow coming soon.[/]")
        # TODO: integrate static analysis

    # ═══════════════════════════════════════════
    #  Tool execution helpers
    # ═══════════════════════════════════════════

    async def _run_tool(self, tool_name: str, params: Dict[str, Any],
                        stdin: Optional[str] = None) -> Dict[str, Any]:
        """Execute a tool via the MCP client, log result, save artifact."""
        assert self.mcp is not None
        if stdin:
            params["_stdin"] = stdin
        result = await self.mcp.execute_tool(tool_name, params, timeout=self.timeout)
        success = result.get("success", False)
        tool_used = result.get("tool_used", tool_name)
        elapsed = result.get("elapsed", 0)
        if success:
            logger.info(f"  ✅ {tool_used} completed in {elapsed}s")
        else:
            err = result.get("error", "unknown")
            logger.warning(f"  ⚠️  {tool_used} failed: {err}")
        # Save raw output
        self._save_text(f"logs/{tool_name}_raw.txt", result.get("output", ""))
        return result

    # ── Parsing ────────────────────────────────

    @staticmethod
    def _lines(result: Dict) -> List[str]:
        output = result.get("output", "")
        return [l.strip() for l in output.strip().split("\n") if l.strip()] if output else []

    @staticmethod
    def _parse_nuclei(output: str) -> List[Dict]:
        findings = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "name": data.get("info", {}).get("name", data.get("template-id", "")),
                    "severity": data.get("info", {}).get("severity", "info"),
                    "template_id": data.get("template-id", ""),
                    "matched_at": data.get("matched-at", data.get("host", "")),
                    "type": data.get("type", ""),
                    "evidence": data.get("extracted-results", data.get("matcher-name", "")),
                })
            except json.JSONDecodeError:
                # Non-JSON line (e.g. [template-id] [severity] host)
                if "[" in line:
                    findings.append({"name": line, "severity": "info", "raw": True})
        return findings

    # ── File helpers ───────────────────────────

    def _save_json(self, rel_path: str, data: Any):
        p = self.output_dir / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def _save_text(self, rel_path: str, text: str):
        p = self.output_dir / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def _save_lines(self, rel_path: str, lines: List[str]):
        self._save_text(rel_path, "\n".join(lines))


# ═══════════════════════════════════════════════
#  Print helpers
# ═══════════════════════════════════════════════

def print_tool_status(tool_server: MCPToolServer):
    available = tool_server.get_available_tools()
    if HAS_RICH:
        table = Table(title="🔧 Tool Status", show_lines=False)
        table.add_column("Tool", style="cyan")
        table.add_column("Status", style="bold")
        for name, ok in sorted(available.items()):
            table.add_row(name, "[green]✅ installed[/]" if ok else "[red]❌ missing[/]")
        console().print(table)
    else:
        print("\n🔧 Tool Status:")
        for name, ok in sorted(available.items()):
            print(f"  {'✅' if ok else '❌'} {name}")

    total = len(available)
    ok = sum(1 for v in available.values() if v)
    rprint(f"\n  [bold]{ok}/{total}[/bold] tools available\n")


def print_workflows():
    if HAS_RICH:
        from hydra.workflows import list_workflows
        table = Table(title="📋 Available Workflows")
        table.add_column("Name", style="cyan bold")
        table.add_column("Description")
        table.add_column("Duration", style="dim")
        for wf in list_workflows():
            table.add_row(wf["name"], wf["description"], wf.get("duration", "?"))
        console().print(table)
    else:
        print("\n📋 Available Workflows:")
        for w in AVAILABLE_WORKFLOWS:
            print(f"  • {w}")
    print()


def print_summary(summary: Dict):
    """Print a final scan summary."""
    rprint("\n[bold]═══════════════════════════════════════════════")
    rprint("[bold cyan]📊 THENOTHING Scan Summary[/bold cyan]")
    rprint("[bold]═══════════════════════════════════════════════")
    rprint(f"  Target:     [bold]{summary['target']}[/bold]")
    rprint(f"  Workflow:   {summary['workflow']}")
    rprint(f"  Duration:   {summary['elapsed_s']}s")

    recon = summary.get("recon", {})
    if recon:
        rprint(f"\n  [bold]Recon:[/bold]")
        for k, v in recon.items():
            rprint(f"    {k}: {v}")

    fc = summary.get("findings_count", 0)
    colour = "red" if fc > 0 else "green"
    rprint(f"\n  [bold]Findings: [{colour}]{fc}[/{colour}][/bold]")

    if fc > 0:
        for f in summary.get("findings", [])[:20]:
            sev = f.get("severity", "info")
            sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}
            sc = sev_colors.get(sev, "dim")
            rprint(f"    [{sc}][{sev.upper():8s}][/{sc}] {f.get('name', 'N/A')}")
            if f.get("matched_at"):
                rprint(f"             [dim]→ {f['matched_at']}[/dim]")

    rprint(f"\n  Output:     [dim]{summary.get('output_dir', '')}[/dim]")
    rprint("[bold]═══════════════════════════════════════════════\n")


# ═══════════════════════════════════════════════
#  Entry points
# ═══════════════════════════════════════════════

async def async_main():
    parser = build_parser()
    args = parser.parse_args()

    # Banner
    print(BANNER)
    setup_logging(args.verbose)

    # ── List workflows ─────────────
    if args.list_workflows:
        print_workflows()
        return

    # ── Check / install tools ──────
    if args.check_tools or args.install_tools:
        ts = MCPToolServer()
        await ts.initialize()
        print_tool_status(ts)
        if args.install_tools:
            from hydra.bootstrap.installer import auto_install_all
            auto_install_all()
        return

    # ── Target required below ──────
    if not args.target:
        parser.error("the following arguments are required: -t/--target")

    # ── Run workflow ───────────────
    engine = HydraEngine(
        target=args.target,
        workflow=args.workflow,
        output_dir=args.output_dir,
        timeout=args.timeout,
        scope_url=args.scope_url or "",
    )
    await engine.init()
    summary = await engine.run()
    print_summary(summary)


def entry():
    """Console script entry point."""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        rprint("\n[yellow]⚠️  Interrupted — shutting down...[/yellow]")


if __name__ == "__main__":
    entry()
