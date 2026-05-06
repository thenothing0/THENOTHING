"""
╔══════════════════════════════════════════════════════════════╗
║  HYDRA Main — Entry point for the Bug Bounty OS             ║
║  Usage: python -m hydra.main --target example.com           ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import asyncio
import logging
import logging.config
import signal
import sys
import time
from typing import List

from hydra.config import get_config, LOGS_DIR
from hydra.memory.bus import MemoryBus
from hydra.mcp.tool_server import MCPToolServer
from hydra.mcp.client import MCPClient
from hydra.mcp.http_server import MCPHTTPServer
from hydra.ai.router import AIRouter
from hydra.learning.engine import LearningEngine
from hydra.graph.engine import AttackGraph
from hydra.swarm.coordinator import CoordinatorAgent
from hydra.swarm.recon_agent import ReconAgent
from hydra.swarm.vuln_research_agent import VulnResearchAgent
from hydra.swarm.exploit_hypothesis_agent import ExploitHypothesisAgent
from hydra.swarm.validation_agent import ValidationAgent
from hydra.swarm.reporting_agent import ReportingAgent
from hydra.bootstrap.installer import get_missing_tools, auto_install_all

BANNER = r"""
╔═══════════════════════════════════════════════════════════════╗
║  ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗                    ║
║  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗                   ║
║  ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║                    ║
║  ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║                    ║
║  ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║                    ║
║  ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝                 ║
║                                                                ║
║  AI Bug Bounty Operating System v1.0.0                         ║
║  Multi-Agent Swarm • MCP Tools • Self-Learning                 ║
╚═══════════════════════════════════════════════════════════════╝
"""

logger = logging.getLogger("hydra")


def setup_logging(verbose: bool = False):
    """Configure logging."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(str(LOGS_DIR / "hydra.log"), encoding="utf-8"),
        ],
    )
    # Quiet noisy libs
    for lib in ["urllib3", "aiohttp", "asyncio"]:
        logging.getLogger(lib).setLevel(logging.WARNING)


def parse_args():
    parser = argparse.ArgumentParser(
        description="HYDRA — AI Bug Bounty Operating System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain or URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--install-tools", action="store_true",
                        help="Auto-install missing security tools")
    parser.add_argument("--check-tools", action="store_true",
                        help="Check tool availability and exit")
    parser.add_argument("--mcp-only", action="store_true",
                        help="Start MCP server only (no scan)")
    parser.add_argument("--mcp-port", type=int, default=8900,
                        help="MCP server port (default: 8900)")
    parser.add_argument("--no-ai", action="store_true",
                        help="Disable AI features")
    parser.add_argument("--agents", type=int, default=1,
                        help="Number of worker agents per type (default: 1)")
    return parser.parse_args()


async def main():
    args = parse_args()
    print(BANNER)
    setup_logging(args.verbose)
    config = get_config()
    
    # ── Tool checks ──────────────────────────
    if args.check_tools or args.install_tools:
        missing = get_missing_tools()
        if missing:
            logger.info(f"Missing tools: {', '.join(missing)}")
            if args.install_tools:
                auto_install_all()
        else:
            logger.info("✅ All tools available")
        if args.check_tools:
            return
    
    # ── Initialize subsystems ────────────────
    logger.info("🔧 Initializing HYDRA subsystems...")
    
    # 1. Memory Bus
    bus = MemoryBus(redis_url=config.redis.url)
    await bus.connect()
    
    # 2. MCP Tool Server
    tool_server = MCPToolServer()
    await tool_server.initialize()
    mcp_client = MCPClient(tool_server=tool_server)
    
    # 3. AI Router
    ai_router = None
    if not args.no_ai:
        ai_router = AIRouter()
        await ai_router.initialize()
    
    # 4. Learning Engine
    learning = LearningEngine()
    learning.initialize()
    
    # 5. Attack Graph
    attack_graph = AttackGraph()
    
    # MCP-only mode
    if args.mcp_only:
        mcp_http = MCPHTTPServer(tool_server, port=args.mcp_port)
        await mcp_http.start_standalone()
        return
    
    # ── Start Swarm ──────────────────────────
    logger.info("🐝 Starting agent swarm...")
    
    # Start coordinator
    coordinator = CoordinatorAgent(bus)
    
    # Create agent pools
    tasks: List[asyncio.Task] = []
    agent_instances = []
    
    # Coordinator task
    tasks.append(asyncio.create_task(coordinator.run()))
    
    # MCP HTTP server (background)
    mcp_http = MCPHTTPServer(tool_server, port=args.mcp_port)
    tasks.append(asyncio.create_task(mcp_http.start()))
    
    # Spawn worker agents
    agent_classes = [
        (ReconAgent, {"bus": bus, "mcp_client": mcp_client}),
        (VulnResearchAgent, {"bus": bus, "mcp_client": mcp_client, "ai_router": ai_router}),
        (ExploitHypothesisAgent, {"bus": bus, "ai_router": ai_router}),
        (ValidationAgent, {"bus": bus, "ai_router": ai_router, "learning_engine": learning}),
        (ReportingAgent, {"bus": bus, "ai_router": ai_router}),
    ]
    
    for agent_cls, kwargs in agent_classes:
        for i in range(args.agents):
            agent = agent_cls(**kwargs)
            agent_instances.append(agent)
            tasks.append(asyncio.create_task(agent.run()))
    
    logger.info(f"✅ {len(agent_instances)} agents running across {len(agent_classes)} types")
    
    # ── Launch Scan ──────────────────────────
    logger.info(f"🎯 Starting scan: {args.target}")
    scan_id = await coordinator.start_scan(args.target)
    logger.info(f"📋 Scan ID: {scan_id}")
    
    # ── Monitor Loop ─────────────────────────
    try:
        while True:
            await asyncio.sleep(5)
            status = await coordinator.get_scan_status(scan_id)
            if not status:
                continue
            
            scan_status = status.get("status", "unknown")
            current_phase = status.get("current_phase", "?")
            completed_phases = status.get("phases_completed", [])
            
            logger.info(
                f"📊 Scan {scan_id}: status={scan_status} "
                f"phase={current_phase} completed={completed_phases}"
            )
            
            if scan_status in ("completed", "cancelled", "failed"):
                break
    
    except KeyboardInterrupt:
        logger.info("⚠️  Interrupted — shutting down...")
    
    finally:
        # ── Shutdown ─────────────────────────
        logger.info("🛑 Shutting down HYDRA...")
        
        # Capture final status BEFORE disconnecting
        final_status = None
        try:
            final_status = await bus.get_state(f"scan:{scan_id}")
        except Exception:
            pass
        
        await coordinator.stop()
        for agent in agent_instances:
            await agent.stop()
        
        for t in tasks:
            t.cancel()
        
        await bus.disconnect()
        
        # Print final summary
        if final_status:
            elapsed = final_status.get("completed_at", time.time()) - final_status.get("started_at", 0)
            logger.info(f"📊 Scan completed in {elapsed:.1f}s")
            logger.info(f"   Phases: {final_status.get('phases_completed', [])}")
        
        # Learning summary
        summary = learning.get_summary()
        logger.info(f"🧠 Learning: {summary['total_findings_recorded']} findings recorded")
        
        # Attack graph summary
        logger.info(f"🕸️  {attack_graph.summary()}")
        
        logger.info("👋 HYDRA shutdown complete")


def entry():
    """Console script entry point."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    entry()
