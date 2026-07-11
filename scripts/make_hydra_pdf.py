#!/usr/bin/env python3
"""
Generate HYDRA_Project_Documentation.pdf — a comprehensive, professionally styled
project document rendered from HTML/CSS via WeasyPrint.

Single source of truth: the HYDRA System Context (architecture memory) + the live
catalogs. Deterministic content; no network.
"""
from __future__ import annotations

import html as _html
from datetime import date
from pathlib import Path

from weasyprint import HTML

OUT_NAMES = ["HYDRA_Project_Documentation.pdf"]
ROOT = Path(__file__).resolve().parents[1]
TARGETS = [ROOT, ROOT / "artifacts"]
TODAY = date.today().isoformat()


# ── tiny HTML builders ───────────────────────────────────────────────────────────
def esc(s) -> str:
    return _html.escape(str(s))


def table(headers, rows, cls="data"):
    h = "".join(f"<th>{esc(c)}</th>" for c in headers)
    body = ""
    for r in rows:
        body += "<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>"
    return f'<table class="{cls}"><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>'


def h2(num, title, anchor):
    return f'<h2 id="{anchor}"><span class="secnum">{num}</span>{esc(title)}</h2>'


def h3(title):
    return f"<h3>{esc(title)}</h3>"


def callout(text, kind="note"):
    return f'<div class="callout {kind}">{text}</div>'


def code(text):
    return f"<pre class=\"code\">{esc(text)}</pre>"


# ── content sections ─────────────────────────────────────────────────────────────
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
        h2("1", "Project Overview", "overview")
        + "<p>HYDRA is an <b>Offensive Knowledge Operating System</b> — a layered, pure-Python "
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
 (source,    (health,      (workflow   (forecast,    (metadata-    (trends, decay,
  verif,      drift, QA)    state)      strategy)     only digests) momentum, anomaly)
  tool,
  plugin)
"""
    return (
        h2("2", "Architecture Highlights", "highlights")
        + "<p>HYDRA's nine-phase reasoning loop sits on a stack of derived, deterministic "
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
    rows = [[f"<b>{esc(p)}</b>", esc(t), esc(purpose), esc(mcp)] for p, t, purpose, _c, mcp, _i in PHASES]
    out = (h2("3", "Architecture Lineage (Phases A -> O)", "lineage")
           + "<p>Build order is <b>locked A -> O</b>. Every phase is derived/advisory unless noted; "
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
    out = (h2("4", "The Seven Agents", "agents")
           + "<p>Introduced in <b>Phase H</b> (declarative agents) and made executable-as-<i>state</i> "
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
    return (h2("5", "MCP Tools (108)", "mcp")
            + "<p>All tooling is exposed to the LLM operator through the <b>hydra-security</b> MCP "
            "server (<code>python mcp_server.py</code>, stdio or SSE). A committed contract baseline "
            "and a CLAUDE.md doc-sync test guard against registry drift.</p>"
            + table(["Layer (phase)", "Representative tools"], rows)
            + callout("Beyond the Knowledge-OS phase tools (A-O), the registry also includes the "
                      "legacy operational palette (recon/scan/fuzz) and base tools "
                      "(save_finding, get_findings, generate_report). Live total: <b>108</b>.",
                      "note"))


def sec_capabilities():
    return (h2("6", "Capabilities, Adapters & Plugins", "capabilities")
            + h3("Capabilities")
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
    return (h2("7", "Stores & Databases", "stores")
            + "<p>Every store under <code>data/</code> is <b>derived, disposable, gitignored</b>, and "
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
    return (h2("8", "Architecture Invariants", "invariants")
            + "<p>These invariants are enforced in code and <b>continuously verified by the test "
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
 stores      snapshots      state           forecasts      digests        trends/decay

RULE: every arrow below the wiki is READ-ONLY derived; nothing writes back to
      canonical except the explicit propose-only writers at the top.
"""
    graph = """\
Capabilities (87 core / 153 effective)
  |-- owned by ----> Agents (7)            [Phase H/I, deterministic routing]
  |-- realized by -> Adapters (175/439)    [Phase K, SAFE profiles only]
  |                     '-- health ------> Adapter Intelligence (advisory)
  |-- extended by -> Plugins (6 packs)     [Phase M, declarative + dependency graph]
  |-- planned by --> Runtime Engine        [Phase I, workflow STATE only]
  |-- predicted by-> Simulation            [Phase L, advisory forecasts]
  |-- evaluated by-> Governance            [Phase J, read-only health/drift]
  |-- shared by ---> Federation            [Phase N, metadata-only digests]
  '-- tracked by --> Temporal Intelligence [Phase O, trends/decay/forecast/anomaly]
"""
    return (h2("9", "Data Flow & Architecture Graph", "dataflow")
            + h3("Data flow map") + code(diagram)
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
    body = [[f"<b>{esc(r[0])}</b>"] + [esc(x) if i != 4 else x for i, x in enumerate(r[1:], 1)] for r in rows]
    bench = [
        ["10,000", "0.04 s", "0.30 s", "0.27 s", "0.61 s", "61.5"],
        ["100,000", "0.91 s", "0.38 s", "0.21 s", "1.51 s", "15.1"],
        ["1,000,000", "5.96 s", "1.78 s", "1.61 s", "<b>9.35 s</b>", "<b>9.35</b>"],
    ]
    return (h2("10", "Performance History & Benchmarks", "performance")
            + "<p>Every derived layer targets <b>O(E)</b> (linear in event count); no O(N&sup2;). "
            "Capability/MCP growth across phases:</p>"
            + table(["Phase", "Caps", "Adapters", "Agents", "MCP", "Scaling characteristic"], body)
            + h3("Phase-O temporal benchmark (load-once context, memoized bucketing)")
            + table(["Events (rows)", "ctx build", "trends", "summary", "TOTAL", "&micro;s/event"], bench)
            + callout("Per-event cost <b>decreases then flattens</b> (61 -> 15 -> 9 &micro;s) as fixed "
                      "overhead amortizes &mdash; confirming linear O(E) scaling with no performance "
                      "cliff. 1M rows = 2M derived events (worst case: one high-volume table feeding "
                      "two domains).", "ok")
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
    return (h2("11", "Open Risks", "risks")
            + "<p>Risk history is never deleted &mdash; items move Open &rarr; Mitigated &rarr; "
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
    return (h2("12", "Roadmap (Phase O -> Z)", "roadmap")
            + "<p>All future phases inherit every A&ndash;O invariant: derived, deterministic, "
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
    return (h2("13", "Validation & Quality", "validation")
            + table(["Dimension", "Result"], body)
            + callout("The project follows an <b>Architecture Steward protocol</b>: every phase passes "
                      "a design review, an invariant/safety gate, benchmarks, and an architecture-memory "
                      "update before it is considered complete.", "accent"))


def sec_appendix():
    glossary = [
        ("Capability", "An abstract objective realized by interchangeable tools."),
        ("Adapter", "A capability x tool binding with a SAFE execution profile."),
        ("Agent", "A declarative owner of capability categories that plans & routes (never executes)."),
        ("Canonical wiki", "The single source of truth; only propose-only writers may modify it."),
        ("Derived store", "An event-sourced, disposable, rebuildable learning/intelligence database."),
        ("Two-Signal rule", "Confidence elevates only with two independent corroborating signals."),
        ("MCP", "Model Context Protocol - how the LLM operator invokes HYDRA's 108 tools."),
        ("Rebuild-identical", "Deleting and replaying a derived store yields byte-identical state."),
    ]
    rows = [[f"<b>{esc(t)}</b>", esc(d)] for t, d in glossary]
    return (h2("14", "Appendix &mdash; Glossary & Maintenance", "appendix")
            + table(["Term", "Meaning"], rows)
            + h3("Maintenance protocol")
            + "<p>After any phase completes, the architecture memory "
            "(<code>docs/HYDRA_SYSTEM_CONTEXT.md</code>), <code>CLAUDE.md</code>, and the MCP contract "
            "baseline are updated automatically with the new counts, benchmarks, tests, risks, and "
            "roadmap. The memory file is a first-class architecture artifact.</p>")


# ── assembly ─────────────────────────────────────────────────────────────────────
TOC = [
    ("1", "Project Overview", "overview"),
    ("2", "Architecture Highlights", "highlights"),
    ("3", "Architecture Lineage (Phases A -> O)", "lineage"),
    ("4", "The Seven Agents", "agents"),
    ("5", "MCP Tools (108)", "mcp"),
    ("6", "Capabilities, Adapters & Plugins", "capabilities"),
    ("7", "Stores & Databases", "stores"),
    ("8", "Architecture Invariants", "invariants"),
    ("9", "Data Flow & Architecture Graph", "dataflow"),
    ("10", "Performance History & Benchmarks", "performance"),
    ("11", "Open Risks", "risks"),
    ("12", "Roadmap (Phase O -> Z)", "roadmap"),
    ("13", "Validation & Quality", "validation"),
    ("14", "Appendix - Glossary & Maintenance", "appendix"),
]


def build_toc():
    items = ""
    for num, title, anchor in TOC:
        items += (f'<li><a href="#{anchor}"><span class="t">'
                  f'<span class="n">{esc(num)}</span> {esc(title)}</span></a></li>')
    return f'<section class="toc"><h2 class="toch">Table of Contents</h2><ol>{items}</ol></section>'


CSS = """
@page {
  size: A4; margin: 20mm 16mm 18mm 16mm;
  @bottom-center { content: "HYDRA - Offensive Knowledge OS  ·  Phase O Documentation";
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

/* toc */
.toc { page-break-before: always; }
.toch { border-bottom: 3px solid #00d08a; padding-bottom: 5px; }
.toc ol { list-style: none; padding: 0; margin-top: 8mm; }
.toc li { margin: 0; padding: 0; }
.toc li a { display: block; color: #16314c; padding: 5px 0; border-bottom: 1px dotted #c4d0db; }
.toc li a .n { display: inline-block; width: 9mm; color: #0a7a5a; font-weight: 700; }
.toc li a::after { content: target-counter(attr(href), page); float: right; color: #5b6677; font-weight: 600; }

/* sections */
h2 { page-break-before: always; border-bottom: 2.5px solid #00d08a; padding-bottom: 5px;
  margin-top: 4mm; font-size: 17pt; }
h2 .secnum { display: inline-block; min-width: 11mm; color: #00a878; }
h3 { font-size: 12pt; margin-top: 6mm; color: #0a4; border-left: 4px solid #00d08a; padding-left: 7px; }
p { margin: 6px 0; }
ul { margin: 6px 0 6px 0; padding-left: 18px; }
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
  <div class="kicker">THENOTHING v7.1 &middot; Claude Code Mode</div>
  <h1>HYDRA<br/>Offensive Knowledge<br/>Operating System</h1>
  <div class="sub">Project Documentation &mdash; Phase O: Temporal Knowledge Intelligence</div>
  <div class="statline">
    <b>15</b> phases (A&ndash;O) &nbsp;&bull;&nbsp; <b>153</b> effective capabilities &nbsp;&bull;&nbsp;
    <b>439</b> adapters &nbsp;&bull;&nbsp; <b>7</b> agents &nbsp;&bull;&nbsp; <b>108</b> MCP tools
  </div>
  <div class="tags">
    <span>Deterministic</span><span>Offline-first</span><span>Rebuild-identical</span>
    <span>Advisory-only</span><span>Canonical-wiki-centered</span><span>Federation-safe</span>
    <span>499 tests green</span>
  </div>
  <div class="meta">
    Comprehensive architecture &amp; design reference &nbsp;|&nbsp; Generated {esc(TODAY)}<br/>
    Single source of truth: docs/HYDRA_SYSTEM_CONTEXT.md (architecture memory)
  </div>
</section>
"""


def main():
    body = (cover() + build_toc()
            + sec_overview() + sec_highlights() + sec_lineage() + sec_agents() + sec_mcp()
            + sec_capabilities() + sec_stores() + sec_invariants() + sec_dataflow()
            + sec_performance() + sec_risks() + sec_roadmap() + sec_validation() + sec_appendix())
    doc = (f"<!doctype html><html><head><meta charset='utf-8'>"
           f"<title>HYDRA Project Documentation</title><style>{CSS}</style></head>"
           f"<body>{body}</body></html>")
    pdf_bytes = HTML(string=doc).write_pdf()
    written = []
    for tdir in TARGETS:
        tdir.mkdir(parents=True, exist_ok=True)
        for name in OUT_NAMES:
            p = tdir / name
            p.write_bytes(pdf_bytes)
            written.append(p)
    for p in written:
        print(f"wrote {p}  ({p.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
