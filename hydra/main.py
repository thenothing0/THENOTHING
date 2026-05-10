"""
╔══════════════════════════════════════════════════════════════╗
║  HYDRA Main v4.0 — Autonomous AI Security Orchestration     ║
║  Usage: python -m hydra.main -t example.com                 ║
║         python -m hydra.main -t example.com -w full_auto    ║
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
  _   ___   ______  ____      _
 | | | \ \ / /  _ \|  _ \    / \    v4.0
 | |_| |\ V /| | | | |_) |  / _ \
 |  _  | | | | |_| |  _ <  / ___ \
 |_| |_| |_| |____/|_| \_\/_/   \_\

  Next-Gen AI Security Orchestration Platform
"""

AVAILABLE_WORKFLOWS = [
    "quick_recon", "full_bounty", "api_only",
    "web3_audit", "blackbox", "code_review",
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
        description="HYDRA — Autonomous AI Security Swarm Platform",
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
    Next-gen HYDRA engine with integrated OSINT, fingerprinting,
    intelligence packs, heuristic reasoning, and hallucination defense.
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

        logger.info("[bold green]✅ HYDRA v4 engine ready[/bold green]")

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
    rprint("[bold cyan]📊 HYDRA Scan Summary[/bold cyan]")
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
