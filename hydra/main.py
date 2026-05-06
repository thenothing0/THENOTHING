"""
╔══════════════════════════════════════════════════════════════╗
║  HYDRA Main — Entry point for the Autonomous Security OS    ║
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

# ── New v2.0 imports ────────────────────────
from hydra.planner import PlannerAgent
from hydra.queue import DistributedTaskQueue, WorkerManager
from hydra.memory.semantic import SemanticMemory
from hydra.consensus import ConsensusEngine
from hydra.validation import AdvancedValidationEngine
from hydra.sandbox import SecuritySandbox, ExecutionPolicy
from hydra.cost import CostTracker, BudgetConfig
from hydra.ai.parallel import ParallelModelEngine
from hydra.ai.safety import HallucinationDefense
from hydra.recovery import WorkflowRecovery
from hydra.observability import metrics, health, tracer
from hydra.reporting import AdvancedReportEngine
from hydra.dashboard import DashboardServer
from hydra.plugins import PluginLoader
from hydra.scope import ScopePolicyEngine, ProgramMemory
from hydra.recon import AdvancedReconEngine
from hydra.learning.knowledge_graph import KnowledgeGraph
from hydra.graph.scoring import GraphScoringEngine
from hydra.graph.visualization import GraphVisualizer
from hydra.output import ArtifactStore

BANNER = r"""
╔═══════════════════════════════════════════════════════════════╗
║  ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗                    ║
║  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗                   ║
║  ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║                    ║
║  ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║                    ║
║  ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║                    ║
║  ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝                 ║
║                                                                ║
║  Autonomous AI Security Orchestration Platform v2.0.0          ║
║  Multi-Agent Swarm • Planner • Consensus • Semantic Memory     ║
║  Attack Graphs • Scope Intelligence • Self-Learning            ║
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
        description="HYDRA — Autonomous AI Security Orchestration Platform",
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
    parser.add_argument("--workflow", type=str, default="full_assessment",
                        choices=["full_assessment", "quick_scan", "api_assessment"],
                        help="Scan workflow template (default: full_assessment)")
    parser.add_argument("--dashboard", action="store_true",
                        help="Enable real-time dashboard")
    parser.add_argument("--scope-file", type=str, default=None,
                        help="Path to scope definition JSON file")
    parser.add_argument("--scope-url", type=str, default=None,
                        help="HackerOne/Bugcrowd/Intigriti program URL")
    parser.add_argument("--platform", type=str, default="custom",
                        choices=["hackerone", "bugcrowd", "intigriti", "custom"],
                        help="Bug bounty platform (default: custom)")
    parser.add_argument("--program", type=str, default="",
                        help="Bug bounty program handle/ID")
    parser.add_argument("--budget", type=float, default=5.0,
                        help="Per-scan AI budget in USD (default: 5.0)")
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
    
    # ═══════════════════════════════════════════
    #  Initialize ALL subsystems
    # ═══════════════════════════════════════════
    logger.info("🔧 Initializing HYDRA v2.0 subsystems...")
    
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
    
    # 4. Learning Engine + Knowledge Graph
    learning = LearningEngine()
    learning.initialize()
    knowledge_graph = KnowledgeGraph()
    knowledge_graph.initialize()
    
    # 5. Attack Graph + Scoring + Visualization
    attack_graph = AttackGraph()
    graph_scorer = GraphScoringEngine(attack_graph)
    graph_visualizer = GraphVisualizer(attack_graph)
    
    # 6. Cost Tracker
    cost_tracker = CostTracker(BudgetConfig(
        per_scan_cap_usd=args.budget,
        daily_cap_usd=config.cost.daily_cap_usd,
        monthly_cap_usd=config.cost.monthly_cap_usd,
    ))
    
    # 7. Distributed Task Queue
    task_queue = DistributedTaskQueue(
        redis_url=config.redis.url,
    )
    await task_queue.connect()
    
    # 8. Worker Manager
    worker_manager = WorkerManager(redis_url=config.redis.url)
    await worker_manager.connect()
    
    # 9. Semantic Memory
    semantic_memory = SemanticMemory(
        persist_dir=config.semantic_memory.persist_dir
    )
    await semantic_memory.initialize()
    
    # 10. Security Sandbox
    sandbox = SecuritySandbox(ExecutionPolicy(
        max_requests_per_second=config.sandbox.max_requests_per_second,
        max_concurrent_tools=config.sandbox.max_concurrent_tools,
    ))
    
    # 11. Consensus Engine
    consensus = ConsensusEngine(
        quorum_size=config.consensus.quorum_size,
        approval_threshold=config.consensus.approval_threshold,
    )
    
    # 12. Advanced Validation Engine
    validation_engine = AdvancedValidationEngine()
    
    # 13. Parallel Model Engine
    parallel_engine = ParallelModelEngine(ai_router=ai_router)
    
    # 14. Hallucination Defense
    hallucination_defense = HallucinationDefense()
    
    # 15. Workflow Recovery
    recovery = WorkflowRecovery(
        checkpoint_dir=config.recovery.checkpoint_dir,
    )
    
    # 16. Advanced Report Engine
    report_engine = AdvancedReportEngine()
    
    # 17. Advanced Recon
    adv_recon = AdvancedReconEngine(mcp_client=mcp_client)
    
    # 18. Scope Policy Engine
    scope_engine = ScopePolicyEngine()
    program_memory = ProgramMemory()
    
    # 19. Plugin Loader
    plugin_loader = PluginLoader(
        plugin_dirs=[config.plugins.plugin_dirs]
    )
    await plugin_loader.discover_and_load()
    
    # 20. Planner Agent (sits above Coordinator)
    planner = PlannerAgent(
        bus=bus, ai_router=ai_router, attack_graph=attack_graph,
    )
    
    # 21. Artifact Output System
    artifact_store = ArtifactStore(base_dir="output")
    artifact_store.initialize_target(args.target)
    
    # ── Wire scope enforcement into MCP + Coordinator ────
    tool_server.set_scope_engine(scope_engine)
    tool_server.set_artifact_store(artifact_store)
    
    # ── Register health checks ──────────────
    health.register_check("memory_bus", lambda: bus.health_check())
    health.register_check("queue", lambda: task_queue.get_metrics())
    health.register_check("cost", lambda: cost_tracker.check_budget())
    
    logger.info("✅ All v2.0 subsystems initialized")
    
    # ═══════════════════════════════════════════
    #  Scope Intelligence — MANDATORY before execution
    # ═══════════════════════════════════════════
    scope_context = None
    if args.scope_url:
        # Auto-detect platform from URL
        scope = await scope_engine.load_from_url(args.scope_url)
        scope_validation = scope_engine.validate_target(args.target)
        if not scope_validation.allowed:
            logger.error(f"🚫 Target NOT in scope: {scope_validation.reason}")
            return
        scope_context = scope_engine.generate_execution_policy()
        sandbox.update_policy(scope_context)
        intel = scope_engine.generate_intelligence_report()
        logger.info(f"🎯 Scope loaded from URL — workflow: {intel.recommended_workflow}")
        if intel.warnings:
            for w in intel.warnings:
                logger.warning(f"  ⚠️  {w}")
        # Save scope intelligence to artifacts
        artifact_store.save_parsed_output(args.target, "logs", "scope_intelligence", {
            "program": scope.program_name, "platform": scope.platform,
            "in_scope": scope.in_scope, "out_of_scope": scope.out_of_scope,
            "policy": scope_context, "directives": intel.planner_directives,
        })
    elif args.scope_file:
        import json as _json
        with open(args.scope_file) as f:
            raw_scope = _json.load(f)
        scope = await scope_engine.load_scope(
            platform=args.platform, raw_scope=raw_scope,
        )
        scope_validation = scope_engine.validate_target(args.target)
        if not scope_validation.allowed:
            logger.error(f"🚫 Target NOT in scope: {scope_validation.reason}")
            return
        scope_context = scope_engine.generate_execution_policy()
        sandbox.update_policy(scope_context)
        logger.info("🎯 Scope validated — target is in-scope")
    elif args.program:
        scope = await scope_engine.load_scope(
            platform=args.platform, program_id=args.program,
        )
        scope_context = scope_engine.generate_execution_policy()
        sandbox.update_policy(scope_context)
    
    # MCP-only mode
    if args.mcp_only:
        mcp_http = MCPHTTPServer(tool_server, port=args.mcp_port)
        await mcp_http.start_standalone()
        return
    
    # ═══════════════════════════════════════════
    #  Start Agent Swarm
    # ═══════════════════════════════════════════
    logger.info("🐝 Starting agent swarm...")
    
    # Start coordinator with scope + planner integration
    coordinator = CoordinatorAgent(bus, scope_engine=scope_engine, planner=planner)
    
    # Create agent pools
    tasks: List[asyncio.Task] = []
    agent_instances = []
    
    # Coordinator task
    tasks.append(asyncio.create_task(coordinator.run()))
    
    # MCP HTTP server (background)
    mcp_http = MCPHTTPServer(tool_server, port=args.mcp_port)
    tasks.append(asyncio.create_task(mcp_http.start()))
    
    # Dashboard (background, optional)
    dashboard = None
    if args.dashboard or config.dashboard.enabled:
        dashboard = DashboardServer(
            host=config.dashboard.host,
            port=config.dashboard.port,
        )
        tasks.append(asyncio.create_task(dashboard.start()))
    
    # Spawn worker agents (ReportingAgent gets validation-first enforcement)
    agent_classes = [
        (ReconAgent, {"bus": bus, "mcp_client": mcp_client}),
        (VulnResearchAgent, {"bus": bus, "mcp_client": mcp_client, "ai_router": ai_router}),
        (ExploitHypothesisAgent, {"bus": bus, "ai_router": ai_router}),
        (ValidationAgent, {"bus": bus, "ai_router": ai_router, "learning_engine": learning}),
        (ReportingAgent, {"bus": bus, "ai_router": ai_router,
                         "artifact_store": artifact_store,
                         "validation_engine": validation_engine,
                         "hallucination_defense": hallucination_defense}),
    ]
    
    for agent_cls, kwargs in agent_classes:
        for i in range(args.agents):
            agent = agent_cls(**kwargs)
            agent_instances.append(agent)
            tasks.append(asyncio.create_task(agent.run()))
    
    logger.info(f"✅ {len(agent_instances)} agents running across {len(agent_classes)} types")
    
    # ═══════════════════════════════════════════
    #  Create Plan and Launch Scan
    # ═══════════════════════════════════════════
    logger.info(f"📋 Creating execution plan for: {args.target}")
    
    # Generate scope intelligence for the Planner
    scope_intel = scope_engine.generate_intelligence_report() if scope_engine.is_loaded else None
    
    # Create plan via Planner Agent (scope-driven)
    plan = await planner.create_plan(
        target=args.target,
        goal=f"Perform {args.workflow.replace('_', ' ')} on {args.target}",
        scope_context=scope_context,
        scope_intelligence=scope_intel,
    )
    logger.info(
        f"📋 Plan: {plan.plan_id} — {len(plan.steps)} steps, "
        f"revision {plan.revision}"
    )
    
    # Feed plan to coordinator — coordinator only executes planner decisions
    await coordinator.accept_plan(scan_id="pending", plan=plan)
    
    # Save plan as artifact
    artifact_store.save_parsed_output(args.target, "logs", "execution_plan", {
        "plan_id": plan.plan_id, "target": plan.target,
        "goal": plan.goal, "total_steps": len(plan.steps),
        "steps": [{"id": s.id, "phase": s.phase, "task_type": s.task_type,
                   "agent_type": s.agent_type, "priority": s.priority}
                  for s in plan.steps],
    })
    
    # Save initial checkpoint
    await recovery.save_checkpoint(
        scan_id=plan.plan_id, phase="plan_created",
        state={"plan_id": plan.plan_id, "target": args.target},
    )
    
    # Start scan via coordinator
    scan_id = await coordinator.start_scan(args.target)
    logger.info(f"🎯 Scan launched: {scan_id}")
    
    # Track metrics
    metrics.inc_counter("scans_started")
    metrics.set_gauge("active_agents", len(agent_instances))
    
    # Update dashboard state
    if dashboard:
        dashboard.state.scans[scan_id] = {
            "target": args.target, "status": "running",
            "plan_id": plan.plan_id, "started_at": time.time(),
        }
    
    # ═══════════════════════════════════════════
    #  Monitor Loop
    # ═══════════════════════════════════════════
    try:
        while True:
            await asyncio.sleep(5)
            status = await coordinator.get_scan_status(scan_id)
            if not status:
                continue
            
            scan_status = status.get("status", "unknown")
            current_phase = status.get("current_phase", "?")
            completed_phases = status.get("phases_completed", [])
            
            # Track progress
            progress = planner.get_plan_progress(plan.plan_id)
            metrics.set_gauge("scan_progress", progress.get("progress_pct", 0))
            
            # Cost check
            budget_status = cost_tracker.check_budget(scan_id)
            if not budget_status.get("budget_ok"):
                logger.warning("⚠️ Budget threshold reached — activating economy mode")
                recovery.enter_degraded_mode("budget_threshold")
            
            logger.info(
                f"📊 Scan {scan_id}: status={scan_status} "
                f"phase={current_phase} completed={completed_phases} "
                f"cost=${budget_status.get('scan_cost', 0):.4f}"
            )
            
            if scan_status in ("completed", "cancelled", "failed"):
                break
    
    except KeyboardInterrupt:
        logger.info("⚠️  Interrupted — shutting down...")
    
    finally:
        # ═══════════════════════════════════════════
        #  Shutdown & Final Reports
        # ═══════════════════════════════════════════
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
        
        await task_queue.disconnect()
        await bus.disconnect()
        
        # Print final summary
        if final_status:
            elapsed = final_status.get("completed_at", time.time()) - final_status.get("started_at", 0)
            logger.info(f"📊 Scan completed in {elapsed:.1f}s")
            logger.info(f"   Phases: {final_status.get('phases_completed', [])}")
        
        # Learning summary
        summary = learning.get_summary()
        logger.info(f"🧠 Learning: {summary['total_findings_recorded']} findings recorded")
        
        # Knowledge graph summary
        kg_summary = knowledge_graph.get_summary()
        logger.info(
            f"🧠 Knowledge: {kg_summary['exploit_patterns_learned']} patterns, "
            f"{kg_summary['workflow_outcomes_recorded']} workflows"
        )
        
        # Attack graph summary
        logger.info(f"🕸️  {attack_graph.summary()}")
        
        # Cost summary
        cost_analytics = cost_tracker.get_analytics()
        logger.info(
            f"💰 Total cost: ${cost_analytics['total_cost']:.4f} "
            f"({cost_analytics['total_requests']} requests)"
        )
        
        # Recovery summary
        recovery_summary = recovery.get_recovery_summary()
        if recovery_summary["total_recoveries"] > 0:
            logger.info(
                f"🔄 Recovery: {recovery_summary['retries']} retries, "
                f"{recovery_summary['skipped']} skipped"
            )
        
        # Consensus summary
        consensus_summary = consensus.get_summary()
        if consensus_summary["total_evaluated"] > 0:
            logger.info(
                f"🤝 Consensus: {consensus_summary['approved']} approved, "
                f"{consensus_summary['rejected']} rejected "
                f"({consensus_summary['avg_agreement']:.0%} agreement)"
            )
        
        logger.info("👋 HYDRA shutdown complete")


def entry():
    """Console script entry point."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    entry()
