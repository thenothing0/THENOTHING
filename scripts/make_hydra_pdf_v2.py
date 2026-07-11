#!/usr/bin/env python3
"""
Generate HYDRA_Project_Documentation_v2.pdf — comprehensive architecture + practical guide.

v2 adds: Installation & Setup, Getting Started, Usage Examples, Wiki Structure & Schema,
Knowledge Promotion Workflow, Offensive Memory System, How to Contribute, Troubleshooting & FAQ
— while keeping every existing section (phases, agents, invariants, roadmap, ...).

Rendered from HTML/CSS via WeasyPrint. Deterministic; no network. A section REGISTRY drives
both the numbered headings and the page-numbered Table of Contents, so numbers never drift.
"""
from __future__ import annotations

import html as _html
from datetime import date
from pathlib import Path

from weasyprint import HTML

OUT_NAMES = ["HYDRA_Project_Documentation_v2.pdf"]
ROOT = Path(__file__).resolve().parents[1]
TARGETS = [ROOT, ROOT / "artifacts"]
TODAY = date.today().isoformat()


# ── tiny HTML builders ───────────────────────────────────────────────────────────
def esc(s) -> str:
    return _html.escape(str(s))


def table(headers, rows, cls="data"):
    h = "".join(f"<th>{esc(c)}</th>" for c in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<table class="{cls}"><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>'


def h3(title):
    return f"<h3>{esc(title)}</h3>"


def callout(text, kind="note"):
    return f'<div class="callout {kind}">{text}</div>'


def code(text, title=None):
    cap = f'<div class="codecap">{esc(title)}</div>' if title else ""
    return cap + f'<pre class="code">{esc(text)}</pre>'


# ══════════════════════════════════════════════════════════════════════════════════
#  SECTION BODIES  (each returns INNER html; the driver adds the numbered <h2>)
# ══════════════════════════════════════════════════════════════════════════════════
def sec_overview():
    rows = [
        ["Current Phase", "<b>O — Temporal Knowledge Intelligence</b>"],
        ["Core capabilities", "87"],
        ["Effective capabilities", "153 (core + 6 plugin packs)"],
        ["Adapters", "175 core / 439 effective"],
        ["Agents", "7"],
        ["Plugins", "6 reference packs"],
        ["MCP tools", "108"],
        ["Tests", "499 passing (6 integration deselected)"],
        ["License", "MIT"],
    ]
    return (
        "<p>HYDRA is an <b>Offensive Knowledge Operating System</b> — a layered, pure-Python "
        "platform that an LLM operator drives through the <b>Model Context Protocol (MCP)</b> to "
        "perform high-quality bug-bounty and offensive-security <b>research within explicit "
        "authorization</b>. It is the engine behind <b>THENOTHING v7.1 — Claude Code Mode</b>.</p>"
        "<p>The platform is built bottom-up across <b>15 locked phases (A&nbsp;&rarr;&nbsp;O)</b>. "
        "Each phase adds a <i>derived, advisory</i> intelligence layer on top of a single "
        "<b>canonical knowledge store</b> (the wiki). Nothing below the wiki ever writes back to it "
        "except through explicit, propose-only paths. Every derived layer is deterministic, "
        "offline-first, and rebuild-identical.</p>"
        + table(["Property", "Value"], rows)
        + callout(
            "<b>Design philosophy:</b> reason before executing, simulate before interacting, "
            "correlate evidence across domains, learn from every outcome — while never silently "
            "mutating the canonical wiki, the promotion rules, or the confidence engine.", "note")
    )


def sec_install():
    reqs = [
        ["Python", "&ge; 3.10 (3.13 recommended)"],
        ["OS", "Linux / Kali (macOS & WSL supported); offline-first core needs no external services"],
        ["Disk", "Modest — derived stores under <code>data/</code> are small SQLite files"],
        ["Recon tooling (optional)", "subfinder, httpx, nuclei, sqlmap, ffuf, katana, gau, dnsx… (only for <i>live</i> recon)"],
        ["MCP client", "Claude Code, Cursor, or Cline (any MCP-compatible client)"],
    ]
    env = [
        ["HYDRA_WIKI_DIR", "Canonical wiki root", "<code>./wiki</code>"],
        ["HYDRA_SOURCE_KEYS", "Comma-separated API keys enabling online recon sources", "(unset = offline)"],
        ["HYDRA_TOR", "Wrap outbound tooling through Tor (1/0)", "<code>0</code>"],
        ["HYDRA_PLUGIN_DIR", "Directory of declarative plugin packs", "<code>hydra/plugins/packs</code>"],
        ["HYDRA_ENFORCE_SCOPE", "Hard scope enforcement for live actions", "on"],
        ["HYDRA_*_DB", "Override any derived store path (SOURCE_LEARNING, VERIFICATION, TOOL_HEALTH, "
         "PLUGIN_HEALTH, DECISION, GOVERNANCE, WORKFLOWS, FEDERATION, TEMPORAL)", "<code>data/*.db</code>"],
    ]
    return (
        h3("System requirements")
        + table(["Requirement", "Detail"], reqs)
        + h3("Clone & install")
        + code("git clone <your-fork-url> hydra\n"
               "cd hydra\n\n"
               "pip install -r requirements.txt        # runtime\n"
               "pip install -r requirements-dev.txt    # tests, linters\n\n"
               "python -m pytest -q                    # 499 passing (6 integration deselected)",
               title="bash")
        + h3("Run the MCP server")
        + "<p>All 108 tools are exposed through the <b>hydra-security</b> MCP server.</p>"
        + code("# stdio (local clients such as Claude Code — auto-loaded via .mcp.json)\n"
               "python mcp_server.py\n\n"
               "# remote / SSE transport (HTTP)\n"
               "python mcp_server.py --transport sse --port 8900\n\n"
               "# verify which optional recon tools are installed\n"
               "#   (MCP tool) check_tools", title="bash")
        + callout("Claude Code auto-loads the server from <code>.mcp.json</code>:<br/>"
                  "<code>{ \"mcpServers\": { \"hydra-security\": "
                  "{ \"command\": \"python\", \"args\": [\"mcp_server.py\"] } } }</code>", "accent")
        + h3("Environment variables")
        + table(["Variable", "Purpose", "Default"], env)
        + h3("Load the wiki & initialize databases")
        + "<p>The canonical wiki ships under <code>wiki/</code>. Derived databases are created "
        "automatically on first use (WAL mode) — there is no migration step. To (re)build the "
        "derived graph index from the canonical wiki, or to seed knowledge:</p>"
        + code("# rebuild the derived graph index from the canonical wiki  (MCP tool)\n"
               "kb_rebuild_index\n\n"
               "# health-check the wiki (orphans, dangling links, type breakdown)\n"
               "kb_lint\n\n"
               "# fuse recon sources into Asset Intelligence (writes the wiki, offline-first)\n"
               "recon_fuse domain=example.com\n\n"
               "# distill a disclosed report into report+intel pages\n"
               "ingest_report path=output/example/report.md target=example", title="MCP tools")
        + callout("Every <code>data/*.db</code> store is <b>derived, disposable, and gitignored</b>. "
                  "Delete any of them and it rebuilds identically from its event log — the canonical "
                  "wiki is the only source of truth.", "ok")
    )


def sec_quickstart():
    return (
        "<p>Once the MCP server is registered, you interact with HYDRA by calling tools from your "
        "MCP client. A typical first session follows the cognitive loop: <b>recall &rarr; plan "
        "&rarr; observe &rarr; simulate &rarr; act &rarr; learn</b>.</p>"
        + h3("First five commands")
        + code("# 1) RECALL — what do we already know? (offensive memory, search-first)\n"
               "kb_recall query=\"idor account takeover\"\n\n"
               "# 2) PLAN — a learning-driven recon plan for a target\n"
               "recon_plan target=example.com\n\n"
               "# 3) OBSERVE — fuse passive recon sources into Asset Intelligence\n"
               "recon_fuse domain=example.com\n\n"
               "# 4) ROUTE — which agent/capability/tool handles this surface?\n"
               "agent_plan target=example.com type=web_app\n\n"
               "# 5) LEARN — how is our knowledge trending over time?\n"
               "temporal_summary", title="MCP session")
        + h3("How interaction works (MCP)")
        + code("LLM operator (Claude Code / Cursor / Cline)\n"
               "      |  calls a tool by name + args\n"
               "      v\n"
               "hydra-security MCP server (mcp_server.py)  -- 108 tools\n"
               "      |  reads/writes ONLY: canonical wiki (propose-only) + derived data/*.db\n"
               "      v\n"
               "returns structured JSON  -->  the operator reasons on it and calls the next tool")
        + callout("Tools are <b>read-only by default</b>. Only a small, explicit set of writers ever "
                  "touch the canonical wiki (<code>recon_fuse</code>, <code>ingest_report</code>, "
                  "<code>confirm_candidate</code>, <code>kb_promote</code>). Everything else "
                  "advises.", "note")
    )


def sec_examples():
    out = "<p>Illustrative calls and (abridged) JSON responses for the most important tools.</p>"
    out += h3("1) Recon Knowledge Fusion — recon_fuse")
    out += ("<p>Collects from policy-allowed sources, dedups, scores confidence by the Two-Signal "
            "rule, and writes canonical Asset Intelligence to the wiki.</p>")
    out += code("recon_fuse domain=example.com capability=discover_subdomains online=false\n\n"
                "{\n"
                "  \"domain\": \"example.com\",\n"
                "  \"assets_written\": 42,\n"
                "  \"two_signal_high_confidence\": 11,\n"
                "  \"sources_used\": [\"crtsh\", \"wayback\", \"dnsx\"],\n"
                "  \"wiki_pages\": [\"assets/api-example-com\", \"assets/dev-example-com\"]\n"
                "}", title="request -> response")
    out += h3("2) Offensive Memory — kb_recall")
    out += code("kb_recall query=\"graphql introspection auth bypass\" limit=3\n\n"
                "{ \"hits\": [\n"
                "  {\"slug\": \"techniques/progressive-auth-probing\", \"type\": \"technique\", "
                "\"score\": 0.88},\n"
                "  {\"slug\": \"intel/viator-expapikey-disclosure\", \"type\": \"intel\", "
                "\"score\": 0.71},\n"
                "  {\"slug\": \"patterns/graphql-sigv4-leak\", \"type\": \"pattern\", "
                "\"score\": 0.64} ] }", title="request -> response")
    out += h3("3) Agents — agent_plan & agent_route")
    out += code("agent_plan target=example.com type=web_app\n"
                "  -> priority-ordered workflow: recon_agent -> attack_surface_agent ->\n"
                "     verification_agent -> correlation_agent -> reporting_agent\n\n"
                "agent_route target=api.example.com type=api\n"
                "{ \"agent\": \"attack_surface_agent\",\n"
                "  \"capability\": \"api_endpoint_discovery\",\n"
                "  \"tool\": \"katana\",            // learning-selected\n"
                "  \"reasoning\": \"api surface; katana highest tool-health for this capability\" }",
                title="request -> response")
    out += h3("4) Temporal Intelligence (Phase O) — temporal_forecast & temporal_decay")
    out += code("temporal_trends domain=capability\n"
                "  -> [{\"entity\":\"subdomain_discovery\",\"direction\":\"rising\",\"slope\":0.42}, ...]\n\n"
                "temporal_forecast domain=verification horizon=3\n"
                "{ \"verification_coverage\": {\"slope\": 0.18,\n"
                "    \"projection\": [4.0, 4.2, 4.4], \"projected_next\": 4.0},\n"
                "  \"method\": \"moving_average + linear_slope (bounded, deterministic)\" }\n\n"
                "temporal_decay\n"
                "{ \"decay_findings\": [\n"
                "   {\"entity\":\"wordpress_xmlrpc\",\"type\":\"capability\",\"severity\":\"high\",\n"
                "    \"rationale\":\"no activity for 24 buckets\",\n"
                "    \"suggested_action\":\"review whether still relevant or re-exercise\"} ] }",
                title="request -> response")
    out += h3("5) Report Intelligence — ingest_report")
    out += code("ingest_report path=output/vk/idor-writeup.md target=vk\n\n"
                "{ \"success\": true,\n"
                "  \"report_page\": \"reports/vk-idor-2026\",\n"
                "  \"intel_page\": \"intel/vk-idor-rootcause\",\n"
                "  \"learning_score\": 8,\n"
                "  \"vuln_class\": \"idor\",\n"
                "  \"unresolved_references\": [\"techniques/object-ref-enumeration\"] }",
                title="request -> response")
    out += h3("6) Pattern Discovery — discover_patterns & confirm_candidate")
    out += code("discover_patterns                 # dry-run; writes nothing\n"
                "  -> candidate: \"cors-misconfig-on-subsidiary\" (2 independent weighted evidences)\n\n"
                "confirm_candidate id=cors-misconfig-on-subsidiary   # the ONLY write path\n"
                "  -> wiki page patterns/cors-misconfig-on-subsidiary (status: candidate, provenance)",
                title="request -> response")
    out += h3("7) Decision Simulation — simulate_workflow")
    out += code("simulate_workflow target=example.com type=web_app\n"
                "{ \"predicted_findings\": 3.4, \"verification_success\": 0.62,\n"
                "  \"completion_probability\": 0.81, \"new_pattern_probability\": 0.27 }",
                title="request -> response")
    out += h3("8) Governance Health — governance_summary")
    out += code("governance_summary\n"
                "{ \"knowledge_health_score\": 78,\n"
                "  \"drift\": {\"count\": 4, \"by_severity\": {\"low\": 3, \"medium\": 1}},\n"
                "  \"decision_intelligence\": { ... },\n"
                "  \"temporal_intelligence\": {\"temporal_health_score\": 71, \"status\": \"healthy\"} }",
                title="request -> response")
    out += callout("Outputs above are <b>illustrative</b> shapes. Exact fields are defined by each "
                   "tool; all are deterministic given the same inputs.", "note")
    return out


def sec_highlights():
    loop = ("Observe -> Understand -> Reason -> Simulate -> Plan -> Execute -> "
            "Validate -> Learn -> Replan")
    diagram = """\
                +------------------------------------------+
                |   CANONICAL WIKI  (single source truth)  |  <- promotion.py / confidence.py (frozen)
                +-------------------+----------------------+
                                    | rebuild (read-only, one-way)
   +-------------+------------+-----+------+-------------+-------------+
   v             v            v            v             v             v
 LEARNING    GOVERNANCE    RUNTIME     SIMULATION    FEDERATION    TEMPORAL (Phase O)
"""
    return (
        "<p>HYDRA's nine-phase reasoning loop sits on a stack of derived, deterministic "
        "subsystems:</p>"
        + callout(f"<b>Reasoning loop:</b> {esc(loop)}", "accent")
        + code(diagram)
        + "<ul>"
        "<li><b>Capability-first.</b> Everything is a <i>capability</i> (e.g. "
        "<code>subdomain_discovery</code>), realized by interchangeable <i>tools</i> via "
        "<i>adapters</i>.</li>"
        "<li><b>Derived &amp; rebuildable.</b> Every learning/intelligence store is a pure function "
        "of an append-only event log; delete it and it rebuilds identically.</li>"
        "<li><b>Advisory-only.</b> Simulation, governance, federation and temporal layers "
        "<i>recommend</i>; they never execute, confirm, promote, or exploit.</li>"
        "<li><b>Offline-first &amp; deterministic.</b> Given a fixed injected clock, outputs are "
        "byte-identical (rebuild-identical).</li>"
        "</ul>"
    )


PHASES = [
    ("A", "Offensive Knowledge OS Foundations",
     "Capability-first recon + a machine-operable wiki as the single canonical store.",
     "CapabilityRegistry, WikiStore, recon-fusion (Two-Signal confidence), graph index, "
     "promotion.py, confidence.py, safety/test harness.", "+10",
     "Wiki canonical; promotion/confidence introduced and frozen thereafter."),
    ("B", "Report Intelligence",
     "Distill disclosed reports/writeups into reusable, scored attacker knowledge.",
     "ReportIntelligencePipeline; report+intel pages only; deterministic 1-10 learning score.",
     "+3", "No findings/patterns/chains created; LLM-free deterministic scoring."),
    ("C", "Pattern & Chain Discovery (propose-only)",
     "Cross-document synthesis into pattern/chain candidates.",
     "PatternDiscovery, ChainDiscovery, evidence weighting, confirm_candidate (only write path).",
     "+3", "Discovery is dry-run; canonical pages only via explicit confirm."),
    ("C.5", "Scalability Hardening",
     "Remove O(F^2) chain discovery; rebuild amplification fixes.",
     "Bounded chain discovery; canonical signatures from structured fields only.",
     "0", "Determinism preserved; complexity reduced to O(E)."),
    ("D / D.1", "Source Performance Learning & Opportunity Ranking",
     "Event-sourced learning to prioritize without touching canonical state.",
     "SourceLearningStore, OpportunityScorer; D.1 robustness (no dead-zones).",
     "+4", "Learning derived/rebuildable; never touches promotion/confidence."),
    ("E", "Adaptive Recon & Autonomous Source Selection",
     "Use Phase-D learning to advise recon planning.",
     "AdaptiveSourceSelector, ReconPlanner.", "+2",
     "Advisory; recommends, never executes/confirms/writes."),
    ("F", "Verification Learning & Validation Intelligence",
     "Learn how findings get validated; advisory verification playbooks.",
     "VerificationLearningStore, ValidationIntelligence, PlaybookGenerator, ToolCapabilityRegistry.",
     "+4", "Never auto-confirms/auto-exploits; WAL, idempotent."),
    ("G", "Capability Expansion & Tool Orchestration",
     "Capability-centric catalog v2 (87 caps / 9 categories) + learning tool selector.",
     "CapabilityCatalog, CapabilityCoverage, ToolSelector.", "+4",
     "Capability modeling only; no integrations; read-only."),
    ("H", "Multi-Agent Orchestration",
     "Declarative agents over the capability layer; deterministic routing.",
     "AgentRegistry (6 agents), AgentPlanner; Target->Agent->Capability->Tool.", "+4",
     "Agents never execute/confirm/write; advisory."),
    ("I", "Execution Runtime & Workflow Engine",
     "Deterministic workflow STATE coordination (no execution). Adds mobile_agent -> 87/87 owned.",
     "RuntimeEngine, WorkflowStore (workflows.db).", "+4",
     "Executes no tools; materializes nothing canonical."),
    ("J", "Knowledge Governance, Drift & QA",
     "Derived health/freshness/consistency evaluation.",
     "DriftDetector, KnowledgeQualityAnalyzer, GovernanceIntelligence (knowledge_governance.db).",
     "+6", "Read-only; writes nothing canonical."),
    ("K", "Adapter Framework & Sandboxed Tool Integrations",
     "Capability x tool adapter definitions (175 core) + sandboxed runtime + tool-health learning.",
     "AdapterRegistry, ToolHealthStore, AdapterIntelligence, CapabilityExerciseAnalyzer.", "+6",
     "No offensive execution; only SAFE profiles; unsupported profiles rejected at load."),
    ("L", "Autonomous Knowledge Simulation & Decision Intelligence",
     "Predict workflow/plan/strategy outcomes from historical learning before execution.",
     "SimulationContext (load-once O(E)), WorkflowSimulator, OutcomePredictor, PredictionAnalytics.",
     "+8", "Advisory; governance gains decision_intelligence block; no execution/promotion."),
    ("M", "Capability Marketplace & Plugin Ecosystem",
     "Declarative plugins extend capabilities/adapters/agents. core(87)+plugins(66)=153 effective, "
     "439 adapters.",
     "PluginRegistry, EffectiveCapabilityCatalog, CapabilityDependencyGraph, AgentOwnershipResolver.",
     "+12", "Globally-unique capability ids; no plugin execution; promotion/confidence untouched."),
    ("N", "Federated Knowledge Exchange & Intelligence Mesh",
     "Exchange anonymized, aggregated intelligence digests between instances - metadata only.",
     "federation/: safety guard, KnowledgeExchangeStore, FederationRegistry, KnowledgeDigestGenerator, "
     "IntelligenceMesh, ConsensusEngine, FederationMarketplace.", "+10",
     "Metadata-only (assert_safe on export+import); advisory; promotion/confidence untouched."),
    ("O", "Temporal Knowledge Intelligence",
     "Understand how knowledge evolves over time: trends, momentum, decay, forecasts, anomalies.",
     "temporal_intel/: TemporalStore, TemporalContext (load-once, memoized), TrendAnalyzer, "
     "MomentumAnalyzer, TemporalForecastEngine, DecayAnalyzer, TemporalAnomalyDetector, "
     "TemporalAdvisor, TemporalIntelligence.", "+6",
     "Derived/advisory/deterministic; no wiki mutation; promotion/confidence untouched."),
]


def sec_lineage():
    rows = [[f"<b>{esc(p)}</b>", esc(t), esc(purpose), esc(mcp)]
            for p, t, purpose, _c, mcp, _i in PHASES]
    out = ("<p>Build order is <b>locked A -> O</b>. Every phase is derived/advisory unless noted; "
           "none mutate promotion.py, confidence.py, or canonical wiki behavior.</p>"
           + table(["Phase", "Theme", "Purpose", "MCP &Delta;"], rows))
    out += "<h3>Per-phase detail</h3>"
    for p, t, purpose, comps, mcp, inv in PHASES:
        out += (f'<div class="phasecard"><div class="phasehd">Phase {esc(p)} &mdash; {esc(t)} '
                f'<span class="pill">MCP {esc(mcp)}</span></div>'
                f"<p><b>Purpose.</b> {esc(purpose)}</p>"
                f"<p><b>Components.</b> {esc(comps)}</p>"
                f"<p><b>Invariants preserved.</b> {esc(inv)}</p></div>")
    return out


AGENTS = [
    ("recon_agent", 10, "reconnaissance, infrastructure",
     "Discover and map the external attack surface - subdomains, DNS, ASN/CIDR, ports, services, "
     "tech, TLS.", "subdomain, dns_record, ip, asn, open_port, service, technology, host"),
    ("attack_surface_agent", 8, "web, api",
     "Enumerate the web/API surface and probe for vulnerability candidates (advisory).",
     "endpoint, parameter, url, xss, sqli, ssrf, graphql, vulnerability"),
    ("cloud_agent", 7, "cloud, secrets, source_code",
     "Discover cloud assets, leaked secrets, and source-code / dependency exposures.",
     "cloud_bucket, cloud_misconfig, secret, credential, repository, dependency_vuln"),
    ("verification_agent", 6, "verification",
     "Validate suspected findings using verification playbooks - never auto-confirms.",
     "idor, ssrf, auth_bypass, open_redirect, csrf, xss, sqli, takeover"),
    ("mobile_agent", 6, "mobile",
     "Static-analyze mobile apps (APKs): secret/endpoint extraction, deeplink and cert-pinning "
     "checks. Added in Phase I - closes capability ownership to 87/87.",
     "mobile_finding, secret, credential, endpoint, internal_host, deeplink, cert_pinning"),
    ("correlation_agent", 5, "(cross-cutting)",
     "Correlate findings and report-intel into patterns and chains - propose-only; promotion "
     "rules unchanged.", "pattern, chain"),
    ("reporting_agent", 3, "(cross-cutting)",
     "Synthesize confirmed knowledge into structured bug-bounty reports.", "report"),
]


def sec_agents():
    rows = [[f"<b>{esc(a)}</b>", esc(pr), esc(cat), esc(resp)] for a, pr, cat, resp, _o in AGENTS]
    diagram = """\
Target --> agent_route --> Agent --> Capability (category-owned) --> Tool (learning-selected)
                              |                                          |
                              v                                          v
                       Adapter (SAFE profile)                   tool_health learning
                              |
                              v
                      Runtime Engine (workflow STATE only - no execution)
"""
    out = ("<p>Introduced in <b>Phase H</b> (declarative agents) and made executable-as-<i>state</i> "
           "in <b>Phase I</b> (runtime), the agents form a deterministic routing layer. A target is "
           "routed to the right <b>agent</b>, which owns a set of capability <b>categories</b>, each "
           "realized by a learning-selected <b>tool/adapter</b>. Agents <b>never execute tools, "
           "confirm findings, or write the wiki</b> &mdash; they plan and route; the runtime tracks "
           "state only.</p>"
           + table(["Agent", "Priority", "Owns categories", "Responsibility"], rows))
    out += "<h3>Expected outputs per agent</h3>"
    out += table(["Agent", "Expected output asset types"],
                 [[f"<b>{esc(a)}</b>", esc(o)] for a, _p, _c, _r, o in AGENTS])
    out += "<h3>How agents interact with the stack</h3>" + code(diagram)
    out += callout(
        "Routing is deterministic: <code>agent_route</code> maps Target&rarr;Agent&rarr;Capability"
        "&rarr;Tool. Quality is observable via <code>agent_coverage</code> (orphans / overlaps / "
        "bottlenecks) and <code>agent_effectiveness</code> (Phase-L multi-agent simulation). The "
        "effective catalog is <b>153/153 owned, with zero gaps or conflicts</b>.", "accent")
    return out


def sec_mcp():
    layers = [
        ("Recon & Surface", "subfinder_scan, httpx_probe, katana_crawl, gau_urls, dnsx_resolve, "
         "amass_enum, nmap_scan, full_recon, check_tools"),
        ("Vulnerability & Fuzzing", "nuclei_scan, nuclei_scan_list, sqlmap_scan, dalfox_scan, "
         "gxss_check, ffuf_fuzz, dirsearch_scan"),
        ("Fingerprinting", "whatweb_detect, wafw00f_detect"),
        ("Knowledge OS (A-C)", "recon_fuse, kb_recall, kb_lint, kb_promote, kb_rebuild_index, "
         "asset_lookup, graph_neighbors, graph_path, ingest_report, report_lookup, list_reports, "
         "discover_patterns, discover_chains, confirm_candidate"),
        ("Learning & Ranking (D-F)", "record_outcome, source_scores, rank_opportunities, "
         "prioritization_report, select_sources, recon_plan, record_verification, "
         "verification_stats, verification_playbook, tool_capabilities"),
        ("Capabilities & Agents (G-H)", "capability_catalog, capability_coverage, rank_tools, "
         "select_tool, agent_catalog, agent_plan, agent_route, agent_coverage"),
        ("Runtime & Governance (I-J)", "workflow_create, workflow_status, workflow_history, "
         "runtime_summary, governance_summary, drift_report, knowledge_health, stale_entities, "
         "duplicate_patterns, contradiction_report"),
        ("Adapters & Simulation (K-L)", "adapter_catalog, adapter_coverage, adapter_health, "
         "adapter_summary, adapter_select, runtime_analytics, simulate_workflow, simulate_strategy, "
         "predict_outcome, capability_impact, prediction_accuracy, agent_effectiveness, "
         "workflow_optimization, decision_health"),
        ("Marketplace (M)", "plugin_catalog, plugin_summary, plugin_health, plugin_dependencies, "
         "plugin_capabilities, plugin_coverage, capability_graph, dependency_paths, "
         "critical_capabilities, agent_ownership, ownership_conflicts, ecosystem_summary"),
        ("Federation (N)", "federation_peers, federation_summary, export_digest, import_digest, "
         "capability_trends, verification_trends, source_trends, federation_consensus, "
         "ecosystem_opportunities, federation_health"),
        ("Temporal (O)", "temporal_summary, temporal_trends, temporal_forecast, temporal_decay, "
         "temporal_anomalies, temporal_health"),
    ]
    rows = [[esc(name), f"<code>{esc(tools)}</code>"] for name, tools in layers]
    return ("<p>All tooling is exposed to the LLM operator through the <b>hydra-security</b> MCP "
            "server (<code>python mcp_server.py</code>, stdio or SSE). A committed contract baseline "
            "and a CLAUDE.md doc-sync test guard against registry drift.</p>"
            + table(["Layer (phase)", "Representative tools"], rows)
            + callout("Beyond the Knowledge-OS phase tools (A-O), the registry also includes the "
                      "legacy operational palette (recon/scan/fuzz) and base tools "
                      "(save_finding, get_findings, generate_report). Live total: <b>108</b>.",
                      "note"))


def sec_capabilities():
    return (h3("Capabilities")
            + "<p>A <b>capability</b> is an abstract objective (e.g. <code>subdomain_discovery</code>, "
            "<code>port_scanning</code>, <code>xss_probing</code>) independent of any specific tool. "
            "The core catalog holds <b>87</b> capabilities across 9 categories; six declarative "
            "plugin packs raise the <b>effective</b> catalog to <b>153</b>, with globally-unique ids "
            "(duplicates rejected).</p>"
            + h3("Adapters")
            + "<p>An <b>adapter</b> binds one capability to one tool (<code>capability::tool</code>) "
            "with a sandboxed, deterministic definition: execution profile, timeouts, I/O schemas. "
            "Only <b>SAFE profiles</b> (offline / passive / validation / simulation) load; "
            "exploitation / persistence / destructive / weaponized profiles are rejected. The "
            "effective adapter count is <b>439</b> (175 core).</p>"
            + h3("Plugins (6 reference packs)")
            + table(["Pack", "Adds"], [
                ["<b>cloud</b>", "cloud asset / misconfig capabilities"],
                ["<b>mobile</b>", "mobile (APK) analysis capabilities"],
                ["<b>container</b>", "container / K8s exposure capabilities"],
                ["<b>iot</b>", "IoT surface capabilities"],
                ["<b>supply_chain</b>", "dependency / supply-chain capabilities"],
                ["<b>osint</b>", "OSINT enrichment capabilities"],
            ])
            + callout("<b>core_capabilities + plugin_capabilities = effective_capability_catalog.</b> "
                      "A capability dependency graph (requires / enhances / related_to) is "
                      "acyclic-validated; agent ownership is automatic and complete (153/153).",
                      "accent"))


def sec_wiki():
    tree = """\
wiki/
|-- SCHEMA.md        # the config layer - read FIRST every session (conventions + reader contract)
|-- index.md         # content catalog / hub - read SECOND to locate pages
|-- log.md           # append-only change log
|-- _templates/      # page templates: target, asset, technique, intel, hypothesis,
|                    #   observation, finding, pattern, chain, report
|-- targets/         # programs/assets under test (hub pages)
|-- assets/          # discovered assets (subdomains, hosts, endpoints) + Asset Intelligence
|-- techniques/      # reusable attacker methodology (human-readable knowledge)
|-- intel/           # distilled, cross-linked report intelligence (root causes, lessons)
|-- hypotheses/      # exploit theories awaiting validation
|-- findings/        # VALIDATED findings (two independent signals)
|-- patterns/        # recurring lessons synthesized across findings
|-- chains/          # composable multi-step attack paths
'-- reports/         # ingested disclosed reports + submitted report links
"""
    nodetypes = [
        ["target", "A program/asset under test; parent hub for discovered assets."],
        ["asset", "A discovered subdomain/host/endpoint with Two-Signal confidence + sources."],
        ["technique", "Reusable methodology (the human-readable counterpart of a skill)."],
        ["intel", "Distilled, reusable knowledge extracted from a disclosed report."],
        ["observation", "A raw signal compiled from output/ (lowest stage)."],
        ["hypothesis", "An exploit theory with a reasoning trace, awaiting validation."],
        ["finding", "A validated vulnerability (requires two independent signals)."],
        ["pattern", "A recurring lesson synthesized across two or more independent findings."],
        ["chain", "A composable multi-step attack path (e.g. SSRF->Admin->RCE)."],
        ["report", "An ingested disclosed report or a submitted report reference."],
    ]
    fm = """\
---
type: finding
stage: finding
confidence: high
tags: [idor, vk, validated]
created: '2026-06-05'
updated: '2026-06-05'
---

# vk-idor-account-settings

> Validated IDOR on the account-settings endpoint. Two signals: replayed request +
> cross-account read confirmed.

## Evidence
- [[assets/api-vk-com]]
- [[techniques/object-ref-enumeration]]
"""
    return (
        "<p>The wiki is the <b>single canonical knowledge store</b> — the <i>synthesis layer</i> "
        "between raw engagement data and the operator. It follows the <b>LLM-Wiki pattern</b> and is "
        "owned and maintained by the LLM, never a dumping ground for scan output (that stays in "
        "<code>output/</code>).</p>"
        + h3("The three layers")
        + table(["Layer", "Where", "Mutability"], [
            ["<b>Raw sources</b>", "<code>output/&lt;program&gt;/</code>, scope.txt, APK extractions, "
             "disclosed reports", "Immutable — read, never edit"],
            ["<b>The wiki</b>", "<code>wiki/</code>", "Created &amp; maintained by the LLM"],
            ["<b>The schema</b>", "<code>wiki/SCHEMA.md</code>", "Co-evolved by LLM + operator"],
        ])
        + h3("Folder structure")
        + code(tree)
        + h3("index.md & SCHEMA.md")
        + "<p><code>SCHEMA.md</code> is the <b>configuration layer</b>: it defines conventions and a "
        "non-negotiable <b>reader contract</b> — any agent must <i>store, understand, keep in sync, "
        "and verify-before-relying-on</i> the wiki at the start of every session. "
        "<code>index.md</code> is the <b>content catalog</b> (hub) listing targets, techniques, "
        "patterns and chains so a session can locate pages before drilling in.</p>"
        + h3("Page types (NodeTypes) and frontmatter")
        + table(["NodeType", "Meaning"], [[f"<b>{esc(t)}</b>", esc(d)] for t, d in nodetypes])
        + "<p>Every page is Markdown with YAML frontmatter (<code>type</code>, <code>stage</code>, "
        "<code>confidence</code>, <code>tags</code>, timestamps) and <code>[[wikilinks]]</code> that "
        "form the knowledge graph:</p>"
        + code(fm, title="wiki/findings/vk-idor-account-settings.md")
    )


def sec_promotion():
    ladder = """\
   OBSERVATION  ->  INTEL  ->  HYPOTHESIS  ->  FINDING  ->  PATTERN  ->  CHAIN
   (raw signal)   (distilled (exploit       (VALIDATED:   (recurring   (multi-step
                   lesson)    theory)        2 signals)    lesson)      attack path)

   ^------------------ promotion is ONE STEP AT A TIME, forward only ------------------^
   Two independent signals REQUIRED to enter: FINDING, PATTERN, CHAIN
"""
    forbidden = [
        ["observation -> finding", "Must pass through intel/hypothesis + validation first"],
        ["observation -> pattern / chain", "Cannot skip validation"],
        ["intel -> finding", "Intel informs, but a hypothesis must be validated into a finding"],
        ["intel -> pattern / chain", "Patterns/chains are built from validated findings only"],
        ["hypothesis -> pattern / chain", "A hypothesis must become a finding before informing either"],
    ]
    before = """\
# BEFORE - a hypothesis page (unvalidated theory)
---
type: hypothesis
stage: hypothesis
confidence: low
---
# vk-idor-account-settings
> THEORY: account-settings may expose other users' objects via numeric id.
> Falsified if cross-account read returns 403.
"""
    after = """\
# AFTER - promoted to a finding (two independent signals)
#   apply_promotion(page, to=FINDING, sources=[replay, cross_account_read], evidence_count=2)
---
type: finding
stage: finding
confidence: high          # elevated only with 2 independent signals (Two-Signal rule)
---
# vk-idor-account-settings
> VALIDATED: id=1337 returned victim's settings; replay + cross-account read confirm.
"""
    return (
        "<p>Knowledge is never born as a 'finding'. It <b>earns</b> its stage by climbing a strict "
        "ladder, one step at a time, forward only. Validation is mandatory: the engine "
        "(<code>promotion.py</code>, frozen since Phase A) rejects any shortcut.</p>"
        + h3("The promotion ladder")
        + code(ladder)
        + h3("Forbidden transitions (rejected even WITH evidence)")
        + table(["Transition", "Why it is blocked"],
                [[f"<code>{esc(t)}</code>", esc(w)] for t, w in forbidden])
        + h3("Concrete before / after")
        + "<p>A theory about an IDOR starts as a <b>hypothesis</b>. Only after two independent "
        "signals confirm it does <code>apply_promotion</code> move it to <b>finding</b> and elevate "
        "confidence to <b>high</b>:</p>"
        + code(before, title="step 1 - hypothesis")
        + code(after, title="step 2 - validated finding")
        + callout("Once several independent findings share a root cause, the "
                  "<code>correlation_agent</code> proposes a <b>pattern</b> (via "
                  "<code>discover_patterns</code>), and composable findings become a <b>chain</b> — "
                  "but only through the explicit <code>confirm_candidate</code> write path. "
                  "<b>promotion.py and confidence.py are never modified.</b>", "ok")
    )


def sec_memory():
    return (
        "<p>HYDRA's <b>Offensive Memory</b> is the discipline of <i>recalling before planning</i>. "
        "Before any operation, the operator searches the canonical wiki + derived graph index for "
        "prior knowledge — so the system compounds instead of repeating work or re-making known "
        "mistakes.</p>"
        + h3("Recall-first workflow")
        + code("# 1) search prior knowledge (techniques, intel, patterns, findings, lessons)\n"
               "kb_recall query=\"cors subsidiary takeover\"\n\n"
               "# 2) inspect a specific asset's accumulated intelligence\n"
               "asset_lookup slug=api-example-com\n\n"
               "# 3) walk the knowledge graph from a page\n"
               "graph_neighbors slug=techniques/progressive-auth-probing\n\n"
               "# 4) find the shortest attack path between two nodes\n"
               "graph_path from=assets/api-example-com to=chains/ssrf-to-admin",
               title="offensive memory - MCP")
        + h3("Why it matters (the reader contract)")
        + "<p>The wiki's <code>SCHEMA.md</code> binds every session to a non-negotiable contract: "
        "<b>store</b> the relevant knowledge into context, <b>understand</b> it (why a technique "
        "works, which lessons forbid certain framings), <b>keep it in sync</b> (write back durable "
        "learnings), and <b>verify before relying</b> (re-confirm a host/key/version still holds). "
        "Knowledge that is read but not internalized — or learned but not written down — is "
        "considered lost.</p>"
        + callout("Offensive memory also spans the <b>operator memory</b> "
                  "(<code>.claude/.../memory/</code>, cross-session preferences &amp; rejections) and "
                  "<b>skills</b> (executable methodology). The wiki <i>embodies</i> those lessons as "
                  "reusable technique/pattern pages and links back conceptually.", "accent")
    )


def sec_stores():
    rows = [
        ["Learning", "source_learning", "Source performance learning (trust / effectiveness / novelty)"],
        ["Learning", "source_metrics", "Per-source run metrics"],
        ["Learning", "verification_learning", "Verification method / evidence success learning"],
        ["Learning", "tool_health", "Adapter tool-health (reliability / runtime / outcomes)"],
        ["Learning", "plugin_health", "Plugin/capability usage learning"],
        ["Intelligence", "decision_learning", "Simulation / forecasting / strategy (Phase L)"],
        ["Intelligence", "temporal", "Temporal evolution: trends / decay / forecasts (Phase O)"],
        ["Runtime", "workflows", "Deterministic workflow state (Phase I)"],
        ["Governance", "knowledge_governance", "Health / drift snapshots (Phase J)"],
        ["Federation", "federation", "Append-only metadata-only exchange ledger (Phase N)"],
        ["Canonical index", "knowledge_index", "Derived graph index (rebuildable from the wiki)"],
    ]
    body = [[esc(c), f"<code>{esc(n)}.db</code>", esc(d)] for c, n, d in rows]
    return ("<p>Every store under <code>data/</code> is <b>derived, disposable, gitignored</b>, and "
            "rebuildable from its append-only event log (WAL mode, idempotent writes). None is a "
            "second canonical source.</p>"
            + table(["Layer", "Database", "Purpose"], body))


def sec_invariants():
    items = [
        ("Canonical knowledge", "Wiki is the single canonical source; no second canonical source; no dual-write."),
        ("Protected core", "promotion.py and confidence.py are immutable (last touched in Phase A)."),
        ("Discovery", "Propose-only; no autonomous confirmation; no autonomous promotion."),
        ("Learning", "Derived, disposable, event-sourced, rebuild-identical."),
        ("System", "Offline-first; deterministic; advisory-only decision systems; MCP backward-compatible."),
        ("Execution", "No autonomous exploitation; no offensive execution; SAFE adapter profiles only."),
        ("Federation", "Metadata only - never findings, evidence, targets, sources, or secrets."),
        ("Marketplace", "Declarative plugins only - no plugin execution."),
        ("Confidence", "No hidden confidence modification or rewriting."),
    ]
    rows = [[f"<b>{esc(k)}</b>", esc(v)] for k, v in items]
    return ("<p>These invariants are enforced in code and <b>continuously verified by the test "
            "suite</b> (e.g. promotion/confidence immutability checks, no-wiki-mutation tests, "
            "metadata-only federation guards, rebuild-identical determinism tests).</p>"
            + table(["Area", "Invariant"], rows)
            + callout("<b>Invariant regression score at Phase O: 100% preserved (0 regressions).</b>",
                      "ok"))


def sec_dataflow():
    diagram = """\
recon-fusion --+                                  +-- ingest_report / confirm_candidate
               v                                  v     (explicit, propose-only writers)
       +---------------------- CANONICAL WIKI ---------------------+
       |            promotion.py . confidence.py  (frozen)         |
       +-------------------------------+--------------------------+
                                       | rebuild (read-only)
                                       v
                            knowledge_index.db (graph)
                                       | read-only
  +-------------+-------------+--------+--------+-------------+-------------+
  v             v             v                 v             v             v
LEARNING    GOVERNANCE     RUNTIME         SIMULATION     FEDERATION     TEMPORAL
"""
    graph = """\
Capabilities (87 core / 153 effective)
  |-- owned by ----> Agents (7)            [Phase H/I, deterministic routing]
  |-- realized by -> Adapters (175/439)    [Phase K, SAFE profiles only]
  |-- extended by -> Plugins (6 packs)     [Phase M, declarative + dependency graph]
  |-- planned by --> Runtime Engine        [Phase I, workflow STATE only]
  |-- predicted by-> Simulation            [Phase L, advisory forecasts]
  |-- evaluated by-> Governance            [Phase J, read-only health/drift]
  |-- shared by ---> Federation            [Phase N, metadata-only digests]
  '-- tracked by --> Temporal Intelligence [Phase O, trends/decay/forecast/anomaly]
"""
    return (h3("Data flow map") + code(diagram)
            + h3("Architecture relationship graph") + code(graph))


def sec_performance():
    rows = [
        ["A", "87", "-", "-", "10", "recon fusion; index rebuild"],
        ["C.5", "87", "-", "-", "16", "removed O(F^2) -> O(E)"],
        ["D/D.1", "87", "-", "-", "20", "O(E) event-sourced learning"],
        ["F", "87", "-", "-", "26", "O(E), WAL idempotent"],
        ["H", "87", "-", "6", "34", "deterministic routing"],
        ["I", "87", "-", "7", "38", "O(steps) workflow state"],
        ["K", "87", "175", "7", "50", "O(E) tool-health"],
        ["L", "87", "175", "7", "58", "O(E) load-once SimulationContext"],
        ["M", "153", "439", "7", "70", "O(C) incremental plugin loading"],
        ["N", "153", "439", "7", "102", "O(E); ~2 us/event federation reads"],
        ["O", "153", "439", "7", "<b>108</b>", "O(E); 9.35 s @ 1M rows (2M events)"],
    ]
    body = [[f"<b>{esc(r[0])}</b>"] + [esc(x) if i != 4 else x for i, x in enumerate(r[1:], 1)]
            for r in rows]
    bench = [
        ["10,000", "0.04 s", "0.30 s", "0.27 s", "0.61 s", "61.5"],
        ["100,000", "0.91 s", "0.38 s", "0.21 s", "1.51 s", "15.1"],
        ["1,000,000", "5.96 s", "1.78 s", "1.61 s", "<b>9.35 s</b>", "<b>9.35</b>"],
    ]
    return ("<p>Every derived layer targets <b>O(E)</b> (linear in event count); no O(N&sup2;). "
            "Capability/MCP growth across phases:</p>"
            + table(["Phase", "Caps", "Adapters", "Agents", "MCP", "Scaling characteristic"], body)
            + h3("Phase-O temporal benchmark (load-once context, memoized bucketing)")
            + table(["Events (rows)", "ctx build", "trends", "summary", "TOTAL", "&micro;s/event"], bench)
            + callout("Per-event cost <b>decreases then flattens</b> (61 -> 15 -> 9 &micro;s) as fixed "
                      "overhead amortizes &mdash; confirming linear O(E) scaling with no performance "
                      "cliff. 1M rows = 2M derived events (worst case).", "ok")
            + h3("Federation benchmark (Phase N)")
            + "<p>Read cost flat at <b>~1.6&ndash;2.0 &micro;s/event across 2k&ndash;40k events</b> "
            "&mdash; O(E), rebuild-identical digests.</p>")


def sec_risks():
    rows = [
        ["Architectural debt", "Branch/tag drift; no root INDEX.md; source_learning vs source_metrics overlap.", "Open"],
        ["Scaling", "Mesh/consensus re-read patterns; no event-log compaction beyond ~1e6.", "Open"],
        ["Performance", "Per-store SQLite connections, no shared pool (fixed fan-out cost).", "Open"],
        ["Coverage", "Exercise coverage is cold-start low until learning stores fill.", "Mitigated"],
        ["Future", "Apply load-once context pattern to federation; version plugin deps across peers.", "Open"],
    ]
    body = [[f"<b>{esc(a)}</b>", esc(d), esc(s)] for a, d, s in rows]
    return ("<p>Risk history is never deleted &mdash; items move Open &rarr; Mitigated &rarr; "
            "Closed.</p>"
            + table(["Class", "Item", "Status"], body))


def sec_roadmap():
    rows = [
        ["O", "Temporal Knowledge Intelligence", "DELIVERED (current)", "+6 (108)"],
        ["P", "Unified Intelligence & Cross-Store Correlation Layer", "next", "+~4"],
        ["Q", "Federated Trust Graph & Reputation Hardening", "planned", "+~4"],
        ["R", "Reporting & Deliverable Synthesis Intelligence", "planned", "+~3"],
        ["S", "Knowledge Compaction & Snapshotting", "planned", "+~2"],
        ["T", "Multi-Tenant Scope & Isolation", "planned", "+~3"],
        ["U", "Observability & Audit Intelligence", "planned", "+~3"],
        ["V", "Capability Confidence Calibration (advisory)", "planned", "+~2"],
        ["W", "Federated Simulation Exchange", "planned", "+~3"],
        ["X", "Adaptive Roadmap & Self-Planning Intelligence", "planned", "+~2"],
        ["Y", "Cross-Ecosystem Interop & Schema Federation", "planned", "+~2"],
        ["Z", "Architecture Self-Audit & Invariant Enforcement Engine", "planned", "+~3"],
    ]
    body = [[f"<b>{esc(p)}</b>", esc(g), esc(s), esc(m)] for p, g, s, m in rows]
    return ("<p>All future phases inherit every A&ndash;O invariant: derived, deterministic, "
            "offline-first, advisory-only, rebuildable, canonical-wiki-centered.</p>"
            + table(["Phase", "Goal", "Status", "MCP impact"], body))


def sec_validation():
    rows = [
        ["Total tests", "499 passing (6 integration/e2e deselected)"],
        ["Temporal (Phase O)", "23 (18 unit + 5 MCP)"],
        ["Federation (Phase N)", "26 (19 unit + 7 MCP)"],
        ["Determinism", "rebuild-identical under injected clock (digest + summary byte-identical)"],
        ["MCP contract", "108 live = 108 baseline = 108 documented; 0 orphans/dupes/missing"],
        ["Invariants", "promotion/confidence immutable; no-wiki-mutation; metadata-only federation"],
        ["Lint", "ruff clean across all phase surfaces"],
    ]
    body = [[f"<b>{esc(k)}</b>", esc(v)] for k, v in rows]
    return (table(["Dimension", "Result"], body)
            + callout("The project follows an <b>Architecture Steward protocol</b>: every phase passes "
                      "a design review, an invariant/safety gate, benchmarks, and an architecture-memory "
                      "update before it is considered complete.", "accent"))


def sec_contribute():
    return (
        "<p>Contributions are welcome — but HYDRA grows by <b>preserving invariants</b>, never by "
        "trading architecture for speed.</p>"
        + h3("Development workflow")
        + code("git checkout -b phase-x-feature\n"
               "# ... implement (derived, deterministic, advisory) ...\n"
               "python -m pytest -q            # must stay green (499+)\n"
               "ruff check .                   # lint clean\n"
               "# regenerate MCP baseline + update CLAUDE.md if you added tools\n"
               "git commit -m \"...\"           # invariant-preserving, scoped commit", title="bash")
        + h3("Adding a new Capability")
        + "<p>Declare it in <code>capabilities/capability_catalog.yaml</code> (id, category, "
        "target/finding types, verification coverage, offline_runnable, tools). Keep ids "
        "<b>globally unique</b>. No code change is needed for the catalog to pick it up.</p>"
        + h3("Adding a new Adapter")
        + "<p>Adapters are synthesized per <code>capability&times;tool</code>. Provide only a "
        "<b>SAFE execution profile</b> (offline / passive / validation / simulation) with timeouts "
        "and I/O schemas — exploitation/persistence/destructive/weaponized profiles are rejected at "
        "load.</p>"
        + h3("Adding a new Plugin")
        + "<p>Drop a declarative YAML pack into <code>hydra/plugins/packs/</code> "
        "(or <code>$HYDRA_PLUGIN_DIR</code>): capabilities, adapters, agents, dependencies. Plugins "
        "are <b>declarative data only — never executed</b>. The dependency graph must stay acyclic.</p>"
        + h3("Adding a new MCP tool")
        + code("@mcp.tool()\n"
               "def my_tool(arg: str = \"\") -> str:\n"
               "    \"\"\"One-line summary (mirrored into CLAUDE.md).\"\"\"\n"
               "    if (g := _kb_guard()):\n"
               "        return g\n"
               "    return json.dumps(MyAnalyzer().report(), indent=2)\n\n"
               "# then: regenerate tests/mcp/tool_contract_baseline.json\n"
               "#       add the tool to CLAUDE.md (doc-sync test is enforced)", title="mcp_server.py")
        + h3("Guidelines for maintaining invariants")
        + "<ul>"
        "<li><b>Never</b> modify <code>promotion.py</code> or <code>confidence.py</code>.</li>"
        "<li><b>Never</b> add a second canonical source or a dual-write; the wiki is canonical.</li>"
        "<li>New intelligence layers must be <b>derived + advisory + deterministic</b> "
        "(inject clocks, sort outputs, key by stable ids, rebuild-identical).</li>"
        "<li>No autonomous confirmation, promotion, exploitation, or tool execution.</li>"
        "<li>Federation payloads are <b>metadata only</b>; run them through the safety guard.</li>"
        "</ul>"
        + callout("New phases follow the <b>Architecture Steward protocol</b>: design review &rarr; "
                  "invariant/safety gate &rarr; implementation &rarr; benchmarks &rarr; "
                  "architecture-memory update (<code>docs/HYDRA_SYSTEM_CONTEXT.md</code>).", "accent")
    )


def sec_faq():
    faqs = [
        ("The MCP server starts but knowledge tools return an error.",
         "The knowledge layer failed to import. Tools return "
         "<code>{\"success\": false, \"error\": \"knowledge layer unavailable: ...\"}</code> — check "
         "the traceback, ensure <code>pip install -r requirements.txt</code> succeeded and you run "
         "from the repo root."),
        ("A derived database looks corrupted or stale.",
         "Delete it — every <code>data/*.db</code> is disposable and rebuilds identically from its "
         "event log. Re-run <code>kb_rebuild_index</code> for the graph index."),
        ("Recon tools (subfinder/httpx/...) aren't found.",
         "They are optional and only needed for LIVE recon. Run the <code>check_tools</code> MCP "
         "tool to see what is installed; the core knowledge OS is fully offline-first without them."),
        ("Tests fail on the MCP contract test after I added a tool.",
         "Regenerate <code>tests/mcp/tool_contract_baseline.json</code> and add the tool to "
         "<code>CLAUDE.md</code> — the doc-sync test enforces that code and docs match."),
        ("Why won't it promote my hypothesis straight to a pattern?",
         "By design. <code>FORBIDDEN_PROMOTIONS</code> blocks skipping validation; a hypothesis must "
         "become a finding (two independent signals) before it can inform a pattern or chain."),
        ("Can HYDRA exploit a target automatically?",
         "No. There is no autonomous exploitation path; only SAFE adapter profiles load and a human "
         "stays in the loop for anything offensive. HYDRA advises and orchestrates."),
        ("Temporal tools return nulls / empty results.",
         "Cold start — the learning event logs are empty. Temporal intelligence is derived from "
         "them, so trends/forecasts populate as <code>record_*</code> events accumulate."),
        ("How do I isolate state for testing?",
         "Point the <code>HYDRA_*_DB</code> and <code>HYDRA_WIKI_DIR</code> env vars at a temp "
         "directory; every store and the wiki honor these overrides."),
    ]
    rows = [[f"<b>{esc(q)}</b>", a] for q, a in faqs]
    return (table(["Question / symptom", "Answer"], rows)
            + callout("Still stuck? Read <code>docs/HYDRA_SYSTEM_CONTEXT.md</code> (architecture "
                      "memory) and <code>wiki/SCHEMA.md</code> (knowledge conventions) — they are the "
                      "authoritative references.", "note"))


def sec_appendix():
    glossary = [
        ("Capability", "An abstract objective realized by interchangeable tools."),
        ("Adapter", "A capability x tool binding with a SAFE execution profile."),
        ("Agent", "A declarative owner of capability categories that plans & routes (never executes)."),
        ("Canonical wiki", "The single source of truth; only propose-only writers may modify it."),
        ("Derived store", "An event-sourced, disposable, rebuildable learning/intelligence database."),
        ("Two-Signal rule", "Confidence elevates only with two independent corroborating signals."),
        ("Promotion", "Forward-only stage climb: observation->intel->hypothesis->finding->pattern->chain."),
        ("MCP", "Model Context Protocol - how the LLM operator invokes HYDRA's 108 tools."),
        ("Rebuild-identical", "Deleting and replaying a derived store yields byte-identical state."),
    ]
    rows = [[f"<b>{esc(t)}</b>", esc(d)] for t, d in glossary]
    return (table(["Term", "Meaning"], rows)
            + h3("Maintenance protocol")
            + "<p>After any phase completes, the architecture memory "
            "(<code>docs/HYDRA_SYSTEM_CONTEXT.md</code>), <code>CLAUDE.md</code>, and the MCP contract "
            "baseline are updated automatically with the new counts, benchmarks, tests, risks, and "
            "roadmap. The memory file is a first-class architecture artifact.</p>")


# ══════════════════════════════════════════════════════════════════════════════════
#  SECTION REGISTRY — drives numbering + TOC (order = document order)
# ══════════════════════════════════════════════════════════════════════════════════
SECTIONS = [
    ("Project Overview", "overview", sec_overview),
    ("Installation & Setup", "install", sec_install),
    ("Getting Started (Quick Start)", "quickstart", sec_quickstart),
    ("Usage Examples", "examples", sec_examples),
    ("Architecture Highlights", "highlights", sec_highlights),
    ("Architecture Lineage (Phases A -> O)", "lineage", sec_lineage),
    ("The Seven Agents", "agents", sec_agents),
    ("MCP Tools (108)", "mcp", sec_mcp),
    ("Capabilities, Adapters & Plugins", "capabilities", sec_capabilities),
    ("Wiki Structure & Schema", "wiki", sec_wiki),
    ("Knowledge Promotion Workflow", "promotion", sec_promotion),
    ("Offensive Memory System", "memory", sec_memory),
    ("Stores & Databases", "stores", sec_stores),
    ("Architecture Invariants", "invariants", sec_invariants),
    ("Data Flow & Architecture Graph", "dataflow", sec_dataflow),
    ("Performance History & Benchmarks", "performance", sec_performance),
    ("Open Risks", "risks", sec_risks),
    ("Roadmap (Phase O -> Z)", "roadmap", sec_roadmap),
    ("Validation & Quality", "validation", sec_validation),
    ("How to Contribute", "contribute", sec_contribute),
    ("Troubleshooting & FAQ", "faq", sec_faq),
    ("Appendix - Glossary & Maintenance", "appendix", sec_appendix),
]


def build_toc():
    items = ""
    for i, (title, anchor, _fn) in enumerate(SECTIONS, 1):
        items += (f'<li><a href="#{anchor}"><span class="t">'
                  f'<span class="n">{i}</span> {esc(title)}</span></a></li>')
    return f'<section class="toc"><h2 class="toch">Table of Contents</h2><ol>{items}</ol></section>'


def build_body():
    parts = []
    for i, (title, anchor, fn) in enumerate(SECTIONS, 1):
        parts.append(f'<h2 id="{anchor}"><span class="secnum">{i}</span>{esc(title)}</h2>')
        parts.append(fn())
    return "".join(parts)


CSS = """
@page {
  size: A4; margin: 20mm 16mm 18mm 16mm;
  @bottom-center { content: "HYDRA - Offensive Knowledge OS  ·  Phase O Documentation (v2)";
    font-size: 7.5pt; color: #8a93a6; }
  @bottom-right { content: counter(page) " / " counter(pages); font-size: 8pt; color: #5b6677; }
}
@page cover { margin: 0; @bottom-center { content: none; } @bottom-right { content: none; } }
* { box-sizing: border-box; }
html { font-family: "DejaVu Sans", "Helvetica", sans-serif; font-size: 10.2pt; color: #1c2433; line-height: 1.5; }
h1,h2,h3 { color: #0b2540; font-weight: 700; }
a { color: #0a7a5a; text-decoration: none; }
code { font-family: "DejaVu Sans Mono", monospace; font-size: 8.6pt; background: #eef3f1;
  padding: 0.5px 3px; border-radius: 3px; color: #0a5; }
.codecap { font-family: "DejaVu Sans Mono", monospace; font-size: 7.2pt; color: #00a878;
  background: #06243a; border-radius: 6px 6px 0 0; padding: 3px 10px; margin-bottom: -7px;
  display: inline-block; letter-spacing: 1px; text-transform: uppercase; }
pre.code { font-family: "DejaVu Sans Mono", monospace; font-size: 7.7pt; line-height: 1.35;
  background: #0d1b2a; color: #d6f5e8; padding: 10px 12px; border-radius: 7px;
  white-space: pre; overflow-wrap: normal; border-left: 4px solid #00d08a; }

/* cover */
.cover { page: cover; height: 297mm; color: #eaf6ff; padding: 42mm 20mm 20mm 20mm;
  background: linear-gradient(150deg, #04111d 0%, #07243a 45%, #053a2c 100%); }
.cover .kicker { letter-spacing: 4px; font-size: 11pt; color: #00d08a; text-transform: uppercase; }
.cover h1 { color: #ffffff; font-size: 40pt; line-height: 1.05; margin: 8mm 0 3mm 0; }
.cover .sub { font-size: 15pt; color: #bfe9d8; font-weight: 600; }
.cover .tags { margin-top: 10mm; font-size: 10pt; color: #9fd; }
.cover .tags span { display: inline-block; border: 1px solid #0a7a5a; border-radius: 14px;
  padding: 3px 11px; margin: 3px 4px 3px 0; color: #d6f5e8; }
.cover .meta { position: absolute; bottom: 22mm; font-size: 9.5pt; color: #9bb6c9; }
.cover .statline { margin-top: 12mm; font-size: 12pt; color: #eaf6ff; }
.cover .statline b { color: #00e6a0; }
.cover .vtag { position: absolute; top: 30mm; right: 20mm; border: 1px solid #00d08a;
  color: #00e6a0; border-radius: 6px; padding: 4px 12px; font-size: 10pt; letter-spacing: 2px; }

/* toc */
.toc { page-break-before: always; }
.toch { border-bottom: 3px solid #00d08a; padding-bottom: 5px; }
.toc ol { list-style: none; padding: 0; margin-top: 7mm; }
.toc li a { display: block; color: #16314c; padding: 4.2px 0; border-bottom: 1px dotted #c4d0db; }
.toc li a .n { display: inline-block; width: 9mm; color: #0a7a5a; font-weight: 700; }
.toc li a::after { content: target-counter(attr(href), page); float: right; color: #5b6677; font-weight: 600; }

/* sections */
h2 { page-break-before: always; border-bottom: 2.5px solid #00d08a; padding-bottom: 5px;
  margin-top: 4mm; font-size: 17pt; }
h2 .secnum { display: inline-block; min-width: 11mm; color: #00a878; }
h3 { font-size: 12pt; margin-top: 6mm; color: #0a4; border-left: 4px solid #00d08a; padding-left: 7px; }
p { margin: 6px 0; }
ul { margin: 6px 0; padding-left: 18px; }
li { margin: 3px 0; }

/* tables */
table.data { width: 100%; border-collapse: collapse; margin: 8px 0 12px 0; font-size: 8.8pt; }
table.data th { background: #07243a; color: #eaf6ff; text-align: left; padding: 6px 8px;
  font-weight: 700; border: 1px solid #07243a; }
table.data td { padding: 5px 8px; border: 1px solid #d4dde6; vertical-align: top; }
table.data tr:nth-child(even) td { background: #f3f7fa; }
table.data code { font-size: 7.8pt; }

/* callouts */
.callout { margin: 9px 0; padding: 9px 12px; border-radius: 6px; font-size: 9.3pt; }
.callout.note { background: #eef6ff; border-left: 4px solid #2b6cb0; }
.callout.accent { background: #eafaf3; border-left: 4px solid #00a878; }
.callout.ok { background: #eafbe8; border-left: 4px solid #38a169; }

/* phase cards */
.phasecard { border: 1px solid #d4dde6; border-radius: 7px; padding: 8px 12px; margin: 7px 0;
  background: #fbfdfe; page-break-inside: avoid; }
.phasehd { font-weight: 700; color: #0b2540; font-size: 10.6pt; border-bottom: 1px solid #e2e9ef;
  padding-bottom: 4px; margin-bottom: 4px; }
.pill { float: right; background: #00a878; color: #fff; font-size: 7.7pt; border-radius: 10px;
  padding: 1px 9px; font-weight: 700; }
.phasecard p { margin: 3px 0; font-size: 9pt; }
"""


def cover():
    return f"""
<section class="cover">
  <div class="vtag">v2 &middot; Enhanced</div>
  <div class="kicker">THENOTHING v7.1 &middot; Claude Code Mode</div>
  <h1>HYDRA<br/>Offensive Knowledge<br/>Operating System</h1>
  <div class="sub">Project Documentation &mdash; Phase O: Temporal Knowledge Intelligence</div>
  <div class="statline">
    <b>15</b> phases (A&ndash;O) &nbsp;&bull;&nbsp; <b>153</b> effective capabilities &nbsp;&bull;&nbsp;
    <b>439</b> adapters &nbsp;&bull;&nbsp; <b>7</b> agents &nbsp;&bull;&nbsp; <b>108</b> MCP tools
  </div>
  <div class="tags">
    <span>Install &amp; Quick Start</span><span>Usage Examples</span><span>Wiki Schema</span>
    <span>Promotion Workflow</span><span>Offensive Memory</span><span>Contributing</span>
    <span>Troubleshooting</span><span>499 tests green</span>
  </div>
  <div class="meta">
    Comprehensive architecture + practical guide &nbsp;|&nbsp; Generated {esc(TODAY)}<br/>
    Single source of truth: docs/HYDRA_SYSTEM_CONTEXT.md (architecture memory)
  </div>
</section>
"""


def main():
    doc = (f"<!doctype html><html><head><meta charset='utf-8'>"
           f"<title>HYDRA Project Documentation v2</title><style>{CSS}</style></head>"
           f"<body>{cover()}{build_toc()}{build_body()}</body></html>")
    pdf_bytes = HTML(string=doc).write_pdf()
    for tdir in TARGETS:
        tdir.mkdir(parents=True, exist_ok=True)
        for name in OUT_NAMES:
            p = tdir / name
            p.write_bytes(pdf_bytes)
            print(f"wrote {p}  ({p.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
