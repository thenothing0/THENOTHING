# THENOTHING v7.1 — Full MCP Tool Catalog (`hydra-security`)

Complete reference for the tool palette. Extracted from `CLAUDE.md` to keep the always-loaded operating
spec lean (saves ~10k tokens/session). All tools run through the **`hydra-security`** MCP server (stdio)
and are **deferred / search-loaded** — invoke any tool by name; search this file to pick one. Operating
rules, the authorization gate, the 9-phase cognitive workflow, and report structure live in `CLAUDE.md`.

---

## MCP tool palette (22 tools)

### Authorization Gate (DENY-BY-DEFAULT — gates all active/exploitation actions)
The platform performs active testing / vulnerability **exploitation** ONLY against targets covered by a
registered bug bounty program (a live program's published scope IS written authorization). The gate is
**deny-by-default**: with no covering program, every active action is denied. Absolute prohibitions
(DoS / destructive / data-exfil / social-engineering) are never allowed, even in-scope; exploitation is
**PoC-only** (no exfiltration beyond a minimal proof). Implemented in `hydra/authorization/`
(`BugBountyAuthorizationGate`), reusing `hydra/scope` (program scopes) + `hydra/guardrails` (hard
prohibitions). Call `authorize_target` immediately before any active action and treat a non-authorized
result as a hard stop. Registry is operator-owned (`data/authorized_programs.json`).
- `register_bounty_program` — Register a bug bounty program's published scope = authorization to test its in-scope assets
- `load_bounty_scope` — Source a program's scope live (HackerOne/Bugcrowd/… via `ScopePolicyEngine`) or from a raw dict, and register it with the gate
- `authorize_target` — Deny-by-default check: may the platform take this action against this target? (ALLOW only if in-scope for a registered program; exploitation PoC-only)

### Attack Section (executable, authorization-gated, PoC-only)
The offensive/attack capability (`hydra/attack/`). Every target-naming tool is gated by the
authorization gate above (deny-by-default); payloads are detection / proof-of-concept grade only (no
exfiltration / destruction / DoS). Network sending is confined to an injectable executor (default
dry-run) that runs only after authorization — so MCP `attack_plan` returns a gated plan and never sends
traffic. Modules: `AttackWorkflow` (guarded validate-then-exploit keystone), `PayloadLibrary`
(context-aware + WAF-adaptive), `Bypass403Generator` (automated 403/WAF bypass), `OOBCorrelator`
(out-of-band/blind detection — pluggable listener, no live server), `ChainTemplateEngine` (high-value
chain templates + realized-severity elevation + ATT&CK links), `EvidenceCollector` (reproducible PoC
evidence + curl + screenshot hook), `AttackQueue` (intelligence-driven prioritization).
- `attack_plan` — Authorization-gated attack PLAN: technique → context-aware PoC payloads → candidate chains; dry-run (never sends traffic)
- `attack_execute` — Authorization-gated LIVE PoC execution: sends ONE PoC payload via the gated, rate-limited `HttpExecutor` (`hydra/attack_runtime/`) and returns reproducible evidence; deny-by-default, PoC-only
- `attack_scan` — Authorization-gated DIFFERENTIAL scan: baseline + multi-payload across discovered injection points (query/body/json/header/cookie/path), WAF-adaptive, confirmed/suspected + evidence; deny-by-default, PoC-only, rate-limited
- `attack_access_control` — Authorization-gated IDOR / broken-access-control test: fetches a resource as two identities (`SessionContext`) and diffs; deny-by-default
- `attack_chain_execute` — Authorization-gated chain execution: validates a chain template's testable stages, reports demonstrable depth + realized severity; evidence redacted, no auto-pivot, PoC-only
- `attack_report` — Build a submission-ready report from scan findings (exec summary, confirmed-vs-suspected, PoC + remediation, chaining severity elevation); pure formatting
- `attack_scan_crawled` — Gated scan over a crawl's URLs (pipe `katana_crawl`/`gau_urls` output): de-dupes to distinct injectable endpoints, differential-scans each; deny-by-default, PoC-only
- `attack_login` — Gated login automation: POSTs your test credentials to an in-scope login endpoint, returns the captured session (cookies + bearer) for authenticated tests; deny-by-default
- `oob_confirm` — Confirm a blind/OOB finding: re-mints the deterministic token, polls YOUR collaborator (`OOBPoller` or the persisted interactsh session), correlates interactions → confirmed blind SSRF/XXE/RCE
- `interactsh_register` — Register an interactsh OOB session (RSA keypair + register + persist); returns the OOB domain to embed in payloads; `oob_confirm` then polls + decrypts it (AES-CFB/RSA-OAEP)
- `attack_recon_scan` — One-step recon→scan: crawls an in-scope target (`katana`, optionally `gau`), de-dupes to distinct endpoints, differential-scans each; deny-by-default, PoC-only
- `attack_save_findings` — Close the loop: write TWO-SIGNAL-confirmed findings to the findings store + attack memory AND record each as a verification success → actually feeds Phase-F/P → Phase-S/T/U effectiveness (idempotent; suspected skipped)
- `attack_oob_test` — Active blind-vuln test: injects OOB payloads (SSRF/cmdi into injection points, XXE as XML body) embedding your interactsh callback, polls + correlates → confirmed blind finding; gated, PoC-only
- `attack_campaign` — End-to-end capstone: seeds → multi-class two-signal scan → confirmed → chain match → loop-back publish → submission report, in one gated PoC-only call
- `attack_graphql` — Gated GraphQL testing (introspection / field-suggestion / GET-introspection / batching); detection-only
- `attack_jwt` — JWT analysis + test-token forging (weak-secret, alg=none, HS/RS confusion, kid injection); local crypto, replay against an authorized target
- `attack_web_probe` — Gated web-class probe: `cors` | `cache_poison` | `host_header` (benign markers, detection-only) | `smuggle` (PLAN-ONLY advisory, never auto-sent)
- `attack_race` — Gated, bounded race-condition test (concurrent requests → limit-overrun/TOCTOU candidate); PoC-only, never amplifies
- `attack_privesc` — Gated privilege-escalation / RBAC test: low-priv identity against privileged endpoints (optionally diffed vs admin)
- `attack_api` — Gated OWASP API Top 10 test: `bola` (object-level authz) | `bfla` (function-level authz) | `mass_assignment` (privileged-field binding) | `excessive_data_exposure` (sensitive-field leakage); dual-identity, PoC-only (benign values, leaked keys labelled not stored)
- `attack_oauth` — Gated OAuth/OIDC test: static weaknesses (missing state/PKCE, implicit-flow token leakage, broad scope) + active redirect_uri-validation test (confirmed when an attacker-controlled destination is honoured); never completes a token exchange
- `attack_saml` — SAML Response analysis (local, not gated): flags unsigned / multi-assertion / comment-injection + emits XSW signature-wrapping test vectors; never replayed against the IdP
- `attack_stored` — Gated STORED / second-order test: submits a uniquely-tagged payload at one endpoint then OBSERVES others for the tag (stored XSS / stored SSRF / second-order injection); in-band canary (+ real DOM execution = two-signal) or OOB blind mode; PoC-only
- `attack_param_mine` — Gated parameter mining: Arjun-style reflection-based discovery of hidden query parameters, isolates the responsible param, returns injectable endpoints to feed `attack_scan_crawled`; bounded request budget
- `attack_js_extract` — Extract endpoints / parameter names / high-signal secrets from JavaScript (text or a gated `.js` URL fetch); secret values redacted to previews; feeds the scanners
- `attack_reverify` — Re-verify a stored finding: replays its saved request against a fresh baseline + re-runs two-signal logic → reproduces true/false, and emits a self-contained replayable PoC bundle (curl + request/response + indicators)
- `attack_triage` — Program-aware triage + submission-readiness: maps each finding's CVSS to platform severity (HackerOne/Bugcrowd P-scale) + bounty band, and gates on confirmed / two-signal / proof-attached / in-scope / not-duplicate
- `attack_correlate` — Merge & dedup findings by root cause `(vuln_class, normalized endpoint)` so the same bug via multiple params/endpoints becomes one finding with all instances
- `attack_auth_session` — Gated auth/session test: `csrf` (state-change accepted without/with-bad token + cross-origin) | `cookies` (Set-Cookie security audit) | `reset_poison` (Host/X-Forwarded-Host password-reset poisoning)
- `attack_tech_plan` — Technology-fingerprint attack planner: recommends which vuln classes to test for a detected stack (`whatweb`/headers); pass the same fingerprint to `attack_scan` to float stack-relevant payloads first

Detection fidelity: `attack_scan` accepts `confirm_dom` (real headless-browser XSS confirmation via Playwright — the strong second signal) and `baseline_samples` (baseline stability sampling); the scan also runs a honeypot/trap guard (demotes confirmations on endpoints that return canned "vulnerable" content for benign input) and wires boolean-blind SQLi as an independent corroborating signal.

Injection coverage: `attack_scan` / `attack_scan_crawled` / `attack_recon_scan` / `attack_campaign` also accept `nosqli` | `ldapi` | `prototype_pollution` (NoSQL-operator / LDAP-filter / prototype-pollution injection). The crawled/recon scanners take `concurrency` (bounded parallel endpoints) and `resume` (cross-run dedup) for robustness at scale; the gated executor transparently gunzip/charset-decodes responses and flags SPA shells.

Two-signal note: `attack_scan` now confirms a finding only on TWO INDEPENDENT signals (e.g. reflection + DOM execution); a single signal is reported as `suspected` (the platform's validation-first rule).
- `waf_bypass` — Automated 403/WAF bypass permutation set for a URL (path/method/header/host/encoding); gated
- `generate_payloads` — Context-aware PoC payload library for a vuln class + injection context (no target; not gated)
- `oob_payload` — Out-of-band/blind payloads + a deterministic correlation token under your own OOB domain
- `attack_queue` — Intelligence-driven attack prioritization (severity + chain potential + capability backing); gated

### Post-Exploitation & Impact (gated, authorized-engagement, PoC-only)
Active internal / Active-Directory tradecraft for **demonstrating impact** once an authorized foothold
exists (privilege escalation, lateral movement, AD enumeration, credential-store access). Every
target-naming tool is gated by the SAME deny-by-default authorization gate as the attack section — an
out-of-scope target is a HARD STOP. PoC-only: enumerate and PROVE access; never exfiltrate bulk data,
never destroy, never persist. **Excluded by policy** (CLAUDE.md non-negotiables): DoS, ransomware /
destructive, data-exfiltration, social-engineering / phishing, detection-evasion / AV-EDR-bypass, and
persistent C2 — none belong in an impact PoC.
- `enum4linux_scan` — Gated SMB/AD enumeration (shares, users, groups, policy, OS, RID cycling) via enum4linux-ng
- `smbmap_scan` — Gated SMB share enumeration + per-share read/write permissions (anonymous or authenticated)
- `ldapsearch_query` — Gated LDAP/AD directory query (users/groups/SPNs/GPOs); anonymous or simple-bind
- `netexec_scan` — Gated lateral-movement / AD assessment via netexec (nxc): authenticate across smb/ldap/winrm/mssql/ssh/…, enumerate shares, or run a single BENIGN PoC command for code-exec proof
- `secretsdump_run` — Gated credential-store access (SAM/LSA/cached or NTDS via DRSUAPI); PoC-only, prefer `just_dc_user` to scope a DCSync to one account
- `bloodhound_collect` — Gated AD attack-path collection (bloodhound-python → zipped graph dataset) for offline escalation-path analysis
- `hashcat_crack` — Offline hash cracking via hashcat (LOCAL files only; no target, not gated) — crack hashes captured in an authorized engagement
- `john_crack` — Offline hash cracking via John the Ripper (LOCAL files only; no target, not gated); returns recovered plaintext via `--show`

### General Execution (one shell, runs all of Kali — curl-first)
- `shell_exec` — Run any shell command (the flexible escape hatch for Kali tools without a dedicated wrapper); curl-first, HITL-approved per call, with a HARD catastrophic-command denylist (rm -rf /, fork bomb, mkfs, dd of=/dev/*, shutdown, find -delete) that fires even in operator/YOLO mode; head/tail truncated. Operator owns scope; the four absolute prohibitions are never permitted.

### Dynamic MCP Discovery (spec Part 10)
Operator-declared external MCP servers → discover/validate/namespace their tools with trust scoring + isolation. Unknown-server tools are gated (requires-permission + HIGH risk) and namespaced `mcp:<server>:<tool>` so they can't shadow a core tool; results are byte-capped before materialization (fixes the M10 hostile-server OOM).
- `mcp_declare` — Declare an external MCP server with a trust class (trusted|local|unknown)
- `mcp_servers` — List declared external MCP servers + trust classes
- `mcp_discovered_tools` — List discovered external tools (namespaced) with trust/risk/gating

### HITL Risk Tiers & Pentest Workflow Engine (spec Parts 8 & 9)
Risk-tiered approval policy (advisory; the real modal is the harness's) + the pentest lifecycle state machine. Risk tiers: low (auto) / medium (allow-once|session|deny) / high (once|workflow|deny) / critical (once|deny|emergency-stop) / prohibited (HARD DENY). Operator mode auto-approves friction up to critical; prohibitions + scope gate stay hard. Workflow: scope→recon→enumeration→validation→exploitation→evidence→coverage_review→reporting→done, with approval-gated high-consequence transitions, durable checkpoints, and halt/resume recovery.
- `hitl_classify` — Classify a tool call's risk tier + the approval policy that applies
- `workflow_pentest` — Drive the lifecycle state machine: create|status|advance|checkpoint|halt|resume|list

### Signed Skills 2.0 (spec Part 3)
Multi-format skill manifests (Markdown frontmatter / YAML / JSON) normalized to one canonical form, with SemVer dependencies + acyclic resolution, discovery-order overrides (shadow WARNING when a local skill shadows a SIGNED builtin — PF-3 mitigation), detached HMAC signatures, and trust-gated install (signed-trusted > signed-unknown > unsigned-builtin > unsigned-local > invalid). Keyring via env `HYDRA_SKILL_KEYS`. Skills are DATA — never executed.
- `skill_parse` — Parse a manifest (md|yaml|json) into canonical form (no registration)
- `skill_register` — Parse + register with override precedence + shadow warning
- `skill_verify` — Report a skill's trust level (verifies the detached signature)
- `skill_resolve` — SemVer dependency closure (deps first); errors on missing/mismatch/cycle
- `skill_list` — List registered skills with source + trust level

### 4-Tier Continuous Learning (spec Part 2)
Cross-session lessons across project → personal → cross → org tiers. WRITE is a poison gate (TN-1: steering/exfil text quarantined, never retrieved); RETRIEVAL fences results as untrusted data (TN-2); promotion is approval-gated (org needs ≥2 confirmations); host stored hashed (provenance without leakage). SQLite under `./.thenothing/learning/`.
- `learn_record` — Record a lesson into a tier (poison-gated, secret-redacted, host hashed)
- `learn_search` — Recall lessons (fenced as untrusted data) by token-overlap × recency × trust
- `learn_quarantined` — List poison-gate-flagged lessons for human review
- `learn_review` — Govern a lesson: approve | reject | confirm (confirm raises trust)
- `learn_promote` — Promote a lesson to a broader tier (must broaden; org needs ≥2 confirmations)
- `learn_stats` — Active lessons per tier + quarantined count

### Findings Lifecycle & Coverage (spec Parts 4 & 5)
Production findings state machine (draft→validated→confirmed→reported→remediated) with **evidence-gated confirm** (no confirm without request+response evidence), CVSS→severity, CWE/OWASP, sha256 evidence, root-cause dedup; plus a coverage matrix + scores + the `/next` engine. SQLite under `./findings/`.
- `finding_create` — Create a DRAFT finding (idempotent by vuln_class + normalized endpoint)
- `finding_add_evidence` — Attach redacted, sha256'd evidence (request|response|screenshot|tool_output|curl)
- `finding_transition` — Move through the lifecycle; confirm is evidence-gated; reject from any pre-report state
- `finding_score` — Set CVSS vector + base score → derived severity band
- `finding_list` — List findings (+ summary + dedup clusters) for an engagement
- `coverage_record` — Record/update a coverage tuple (endpoint×method×param×vuln_class) status
- `coverage_summary` — Coverage / attack-surface / risk scores (risk folds in open-finding severities)
- `coverage_next` — The `/next` engine: highest-value untested tuples (auth-area × high-impact class first)

### Browser & Burp Capture
Capture bridge (the bounded, control-byte-scrubbed in-process store the optional `hydra.burp.start_bridge` localhost listener also writes to) + a Playwright JS-rendering crawler. Capture store is LRU-bounded (requests/endpoints/params) and scrubs terminal escapes on insert (hardened per PentesterFlow's M9/M11).
- `burp_status` — Capture-store status: buffered request/endpoint counts + bounds
- `burp_requests` — List recently-captured requests (newest first)
- `burp_endpoints` — Distinct captured endpoints + accumulated parameter names
- `burp_ingest` — Push a captured request (e.g. pasted from Burp) into the store (scrubbed + bounded)
- `burp_ingest_sitemap` — Site-map import: bulk-ingest a JSON array of request records (scrubbed + bounded)
- `burp_issue` — Burp Scanner integration: `add` an issue, `list` issues, or `to_finding` (promote an issue into a DRAFT finding carrying its request/response as evidence — the findings round-trip)
- `burp_repeater` — Fetch a captured request's RAW material for replay/editing
- `burp_timeline` — Session recording: ordered timeline of captured requests + scanner issues
- `browser_crawl` — Gated (deny-by-default) headless-browser crawl: renders JS to surface SPA endpoints, forms, tokens/JWTs, cookies, storage secrets, WebSocket URLs; needs Playwright, degrades gracefully

### Recon & Surface Discovery
- `subfinder_scan` — Fast passive subdomain enumeration
- `amass_enum` — Deep DNS enumeration and network mapping
- `httpx_probe` — Probe hosts for live HTTP services
- `katana_crawl` — Web crawling framework for endpoint discovery
- `gau_urls` — Get historical URLs from Wayback Machine & archives
- `hakrawler_crawl` — Fast web crawler for endpoint discovery
- `dnsx_resolve` — Fast DNS resolution and enumeration
- `subzy_takeover` — Subdomain takeover detection: fingerprints dangling CNAMEs against unclaimed third-party services (GitHub Pages/S3/Heroku/Azure/…); feed subfinder/amass output, single-signal (verify before reporting)

### Vulnerability Scanning
- `nuclei_scan` — Template-based scanner (CVEs, misconfigs, default creds)
- `nuclei_scan_list` — Scan multiple targets at once with Nuclei
- `sqlmap_scan` — Automated SQL injection detection and exploitation
- `dalfox_scan` — XSS parameter analysis and scanning
- `gxss_check` — Check which URL parameters are reflected (XSS grep)

### Fuzzing
- `ffuf_fuzz` — Fast web fuzzer for directories, parameters, vhosts
- `dirsearch_scan` — Directory/file brute-force scanner

### Fingerprinting & Defense Detection
- `whatweb_detect` — Detect web technologies, CMS, frameworks
- `wafw00f_detect` — Detect Web Application Firewalls
- `nmap_scan` — Port scanning and service detection

### Knowledge & Reporting
- `save_finding` — Save validated findings for learning
- `get_findings` — Retrieve past findings from knowledge base
- `generate_report` — Generate structured bug bounty reports
- `full_recon` — Run complete automated recon pipeline
- `check_tools` — Verify which tools are installed

### Offensive Knowledge OS (Phase A — pure-python, offline-first)
Capability-first reconnaissance + a machine-operable wiki (the canonical knowledge store;
a derived graph index accelerates queries). See `wiki/SCHEMA.md`.
- `capability_list` — List declared recon capabilities (discover_subdomains, http_probe, …)
- `capability_sources` — List a capability's sources + metadata + runnable-under-policy flag
- `recon_fuse` — Multi-source recon fusion → Asset Intelligence (Two-Signal confidence), writes the wiki
- `kb_recall` — Offensive Memory: search-first recall of prior knowledge before planning
- `kb_lint` — Wiki/graph health: orphans, dangling links, type breakdown
- `kb_promote` — Promote a page up the hierarchy (forbidden transitions rejected)
- `kb_rebuild_index` — Rebuild the derived graph index from the canonical wiki
- `asset_lookup` — Look up a discovered asset's intelligence (confidence, sources, links)
- `graph_neighbors` — Knowledge-graph neighbors of a page (+ related findings/patterns/chains)
- `graph_path` — Shortest attack path between two knowledge nodes

### Report Intelligence (Phase B — pure-python, offline-first)
Disclosed reports/writeups are learning assets: extract reusable attacker knowledge,
score it, and cross-link the distilled intelligence into the graph. Only `report`/`intel`
pages are ever created (never findings/patterns/chains); missing links are recorded as
`unresolved_references`, never auto-created. Scoring is deterministic, explainable, LLM-free.
- `ingest_report` — Distill a report/writeup → cross-linked `report`+`intel` pages with a 1-10 `learning_score`
- `report_lookup` — Look up an ingested report's metadata, `learning_score`, rationale, and links
- `list_reports` — List ingested reports ranked by `learning_score` (high-value learning first)

### Pattern & Chain Discovery (Phase C — pure-python, offline-first, propose-only)
Cross-document synthesis over the wiki: recurring lessons → `pattern` candidates, composable
multi-step paths → `chain` candidates. Evidence is weighted (validated findings > report-intel;
hypotheses never count) and scored by the existing confidence engine. Discovery is **dry-run**;
canonical pages are created only via an explicit `confirm_candidate`.
- `discover_patterns` — Propose recurring-pattern candidates (≥2 independent weighted evidence, two-signal); ranked, with a machine-readable `explain` block; writes nothing
- `discover_chains` — Propose chain candidates (shared target / asset / program / root-report; bounded, no semantic guessing); writes nothing
- `confirm_candidate` — The only Phase-C write path: concurrency-safe materialization of a candidate into a canonical `pattern`/`chain` page (`status: candidate`, full provenance), or strengthen the existing one

### Source Performance Learning & Opportunity Ranking (Phase D — derived, non-canonical)
An event-sourced learning layer under `data/` (rebuildable, keyed by stable `source.id`).
It improves prioritization over time; it NEVER touches the wiki, promotion rules, or confidence bands.
- `record_outcome` — Verification feedback: attribute a confirmed/rejected candidate to its contributing recon sources (learning only)
- `source_scores` — Read derived per-source `trust` / `novelty` / `effectiveness` scores (rebuildable from raw events)
- `rank_opportunities` — Rank discovery candidates by a non-canonical OpportunityScore (confidence band + source effectiveness + chain potential + novelty + evidence diversity)
- `prioritization_report` — Read-only: which pattern signatures historically succeed, which source categories yield confirmed findings, which evidence combinations get accepted

### Adaptive Recon & Source Selection (Phase E — advisory, learning-driven)
Uses the Phase-D learning to influence reconnaissance planning. Advisory only — recommends, never
executes recon, confirms findings, writes the wiki, or alters confidence/promotion. Deterministic
given a fixed timestamp; bounded (capabilities × sources, O(1) in #findings).
- `select_sources` — Rank a capability's sources by trust/effectiveness(decayed)/novelty/exploration/prior; runnable flag reflects offline/online policy
- `recon_plan` — Ordered, learning-driven recon plan for a target+type: per-capability ranked sources, expected-value estimate, and opportunity-driven emphasis

### Verification Learning & Validation Intelligence (Phase F — advisory, derived)
Learns how findings get validated and generates advisory verification playbooks. Derived/disposable
under `data/` (event-sourced, rebuildable, WAL, idempotent). Advisory only — never auto-confirms,
auto-exploits, writes the wiki, or alters confidence/promotion.
- `record_verification` — Record a verification outcome (success/failure) for a vuln class + method (learning only; idempotent via dedup_key)
- `verification_stats` — Validation intelligence: success stats per method / vuln-class / evidence-type / source-category
- `verification_playbook` — Advisory ranked verification steps for a vuln class + expected value + confidence
- `tool_capabilities` — Modelled tool-capability catalog (recon/web/cloud/verification) with verifier effectiveness; capability modeling for future tool expansion (no integrations)

### Capability Expansion & Tool Orchestration (Phase G — capability-centric, read-only)
A capability-centric catalog v2 (`capabilities/capability_catalog.yaml`, 87 capabilities across 9
categories, each mapping to interchangeable tools) plus a learning-driven tool selector. Capability
modeling only — no integrations. Read-only/advisory; never writes wiki, confidence, or promotion.
- `capability_catalog` — List capability-centric entries (category, target/finding types, verification coverage, offline_runnable, confidence_weight, tools)
- `capability_coverage` — Read-only coverage analysis: uncovered capabilities, weak areas, over-used / under-explored tools
- `rank_tools` — Rank a capability's tools by recon+verification effectiveness + exploration + trust + prior (deterministic)
- `select_tool` — Pick the single best-ranked tool for a capability (advisory)

### Multi-Agent Orchestration (Phase H — declarative agents, read-only/advisory)
Six specialized agents (`capabilities/agent_catalog.yaml`: recon / attack_surface / cloud /
verification / correlation / reporting) orchestrate the capability layer. Deterministic routing
Target→Agent→Capability→Tool. Advisory only — agents never execute tools, confirm findings, write the
wiki, or touch confidence/promotion.
- `agent_catalog` — List agent definitions (responsibilities, allowed categories, priority, expected outputs)
- `agent_plan` — Advisory priority-ordered multi-agent workflow for a target+type (assigned capabilities, expected value, reasoning)
- `agent_route` — Deterministic Target→Agent→Capability→Tool routing (learning-selected tool per capability)
- `agent_coverage` — Agent effectiveness, capability ownership (orphans/overlaps), workflow coverage, bottlenecks, under-utilized agents

### Execution Runtime & Workflow Engine (Phase I — deterministic state, no execution)
A deterministic runtime above the agent layer that coordinates workflow STATE (transitions, retries,
history) in a derived/disposable store (`data/workflows.db`, WAL). Executes no tools, confirms no
findings, materializes nothing into the wiki. Advisory by default. (Phase I also adds `mobile_agent`,
closing capability ownership to 87/87.)
- `workflow_create` — Build a deterministic PENDING workflow (agent→capability→tool plan) in the runtime store; idempotent; executes nothing
- `workflow_status` — Read a workflow + its task states
- `workflow_history` — List workflows, or one workflow's task history
- `runtime_summary` — Runtime intelligence: workflow/agent/failure/retry stats + capability runtime coverage

### Knowledge Governance, Drift & QA (Phase J — derived, read-only/advisory)
Continuously evaluates knowledge health/freshness/consistency from the canonical wiki + derived learning
stores. Derived/disposable governance snapshots under `data/knowledge_governance.db` (WAL). Read-only —
writes nothing canonical, never alters confidence/promotion; all outputs advisory and deterministic.
- `governance_summary` — Health score (0-100) + drift + weakest/healthiest areas + graph health + advisory recommendations
- `drift_report` — Stale patterns/chains/findings/sources, declining source/verification effectiveness, capability drift (severity/confidence/rationale/action)
- `knowledge_health` — Deterministic 0-100 health score with quality metrics (duplication/contradiction/stale/coverage/diversity/graph)
- `stale_entities` — Stale knowledge entities (advisory)
- `duplicate_patterns` — Candidate duplicate patterns (same derived signature) for review
- `contradiction_report` — Hosts with both validated and rejected findings (contradiction candidates)

### Adapter Framework & Sandboxed Tool Integrations (Phase K — derived, advisory, no execution)
Transforms the capability catalog into deterministic, executable **adapter definitions** (one per
capability×tool, 175 total / 87 capabilities) with a sandboxed runtime, event-sourced tool-health
learning, capability exercise metrics, and learning-driven adapter selection. Infrastructure +
orchestration + observability ONLY: NO offensive execution, NO exploitation, NO autonomous actions,
NO wiki mutation. Only SAFE execution profiles (offline/passive/validation/simulation) are permitted;
unsupported (exploitation/persistence/destructive/weaponized) profiles are rejected at load. All state
is derived/disposable under `data/` (rebuildable); promotion.py/confidence.py untouched.
- `adapter_catalog` — List synthesized adapter definitions (execution_profile, timeouts, I/O schemas, offline/validation/simulation flags); filter by capability or category
- `adapter_coverage` — Adapter coverage (by category/profile) + capability EXERCISE metrics (declared/owned/has-adapter/exercised/verified — closes the Phase-J blind spot)
- `adapter_health` — Adapter tool-health (reliability/runtime/success/failure/timeout); one adapter, or healthiest/weakest/failures/timeouts
- `adapter_summary` — Adapter ecosystem summary: totals, utilization, mean reliability, execution/validation/simulation/success/failure/timeout counts
- `adapter_select` — Rank a capability's adapters by learning (effectiveness + reliability + verification + trust + exploration + prior); deterministic, advisory
- `runtime_analytics` — Adapter runtime analytics: utilization, average runtime, timeout distribution, category coverage, execution-profile distribution

### Autonomous Knowledge Simulation & Decision Intelligence (Phase L — derived, advisory, no execution)
Predicts the likely outcome of proposed workflows / agent plans / capability & source selections /
verification playbooks / adapter strategies BEFORE execution, ranks strategies, forecasts outcomes,
measures prediction accuracy over time, and optimizes agent plans — using ONLY the historical learning
stores (source/verification/adapter-health/runtime). Advisory-only, offline-first, deterministic
(injected `now`), rebuildable, non-canonical. NO execution, exploitation, confirmation, promotion,
confidence update, or wiki mutation. A single shared `SimulationContext` loads every store once (O(E));
learning lives in `data/decision_learning.db` (event-sourced, rebuildable). Phase J governance gains a
`decision_intelligence` block (simulation_health / prediction_quality / decision_drift).
- `simulate_workflow` — Predict a workflow/agent-plan's expected findings, verification success, evidence/source diversity, chain & pattern generation, completion probability
- `simulate_strategy` — Compare aggressive / balanced / verification-first strategies by predicted score + confidence + rationale + tradeoffs
- `predict_outcome` — Forecast probabilities: success, stale results, new patterns, new chains, source bias
- `capability_impact` — Per-capability expected value/findings/verification/chain/pattern contribution from learning + adapter health
- `prediction_accuracy` — Forecast accuracy, false positive/negative rates, calibration error, drift (predicted vs actual)
- `agent_effectiveness` — Multi-agent simulation: predicted effectiveness, bottlenecks, capability overlap, redundancy
- `workflow_optimization` — Advisory recommendations (remove/reorder step, add capability/verification, increase diversity) without mutating workflows
- `decision_health` — Decision-intelligence health: simulation health, prediction quality, decision drift, forecast accuracy, prediction/outcome counts

### Capability Marketplace & Plugin Ecosystem (Phase M — declarative plugins, read-only/advisory)
Turns Hydra into an extensible ecosystem: new capabilities/adapters/agents/verification coverage/tool
packs are added through DECLARATIVE plugins (`hydra/plugins/packs/*.yaml`) without modifying core code.
`core_capabilities + plugin_capabilities = effective_capability_catalog` with globally-unique ids
(duplicates rejected). Six reference packs (cloud/mobile/container/iot/supply_chain/osint) → 153
effective capabilities / 439 adapters. A capability dependency graph (requires/enhances/related_to,
acyclic-validated) and automatic agent ownership round it out. Offline-first, deterministic, rebuildable,
advisory-only, non-canonical; NO plugin execution / network / code injection / runtime mutation;
promotion.py/confidence.py and canonical wiki behavior untouched. Plugin usage learning lives in
`data/plugin_health.db` (event-sourced, rebuildable).
- `plugin_catalog` — List installed/available declarative plugins (counts, enabled flag, validation errors)
- `plugin_summary` — Effective capability/adapter composition (core vs plugin) + installed-plugin count
- `plugin_health` — Derived plugin adoption/diversity/effectiveness/health (rebuildable)
- `plugin_dependencies` — Capability dependency edges + plugin version deps a plugin contributes
- `plugin_capabilities` — Capabilities a plugin adds to the effective catalog
- `plugin_coverage` — Capabilities/adapters/agents/verification coverage added + composition + per-plugin
- `capability_graph` — Dependency-graph intelligence: edges by relation, acyclicity/cycles, critical/isolated, coverage gaps
- `dependency_paths` — Shortest directed dependency path source→target (requires+enhances)
- `critical_capabilities` — Most-depended-upon and isolated capabilities
- `agent_ownership` — Automatic agent ownership of capabilities (owner/candidates/confidence)
- `ownership_conflicts` — Agent ownership conflicts and gaps
- `ecosystem_summary` — Full ecosystem intelligence + marketplace recommendations (missing plugins, weak areas, gaps)

### Federated Knowledge Exchange & Intelligence Mesh (Phase N — derived, advisory, metadata-only)
A fully derived, offline-first federation layer (`hydra/federation/`) that lets multiple Hydra
instances exchange ANONYMIZED, AGGREGATED intelligence digests — capability effectiveness,
source-category trends, verification intelligence, plugin/ecosystem metadata — WITHOUT ever
sharing canonical wiki content, evidence, findings, targets, source identities, or secrets. An
append-only ledger (`data/federation.db`, WAL, rebuildable, disposable, idempotent exchange ids)
records peer announcements + imported/exported digests; every write is guarded by a
metadata-only `assert_safe()` that rejects raw knowledge (so federation exchanges metadata only).
A `FederationRegistry` tracks trusted peers (deterministic ids, semantic-version compatibility,
derived trust/health — never credentials); an `IntelligenceMesh` folds imported digests into
ecosystem-wide trends (O(E), grouped aggregation, no O(N²)); a `ConsensusEngine` and
`FederationMarketplace` are ADVISORY ONLY. NO peer execution, NO federation-driven promotion or
confidence adjustment, NO wiki mutation; promotion.py / confidence.py untouched. All deterministic
and rebuild-identical.
- `federation_peers` — Trusted peers: advertised version/protocol, capability/adapter counts, derived trust/health, semver compatibility (metadata only)
- `federation_summary` — Federation ledger at-a-glance: event counts by type, distinct peers, imported/exported digest counts
- `export_digest` — Generate this node's anonymized, deterministic knowledge digest (capability/source/verification/plugin digests; metadata only)
- `import_digest` — Import a peer's digest into the derived ledger (metadata-only guarded, idempotent; never canonical, never promotion/confidence)
- `capability_trends` — Federation-wide capability popularity & effectiveness (adopting peers, total exercise, mean effectiveness)
- `verification_trends` — Federation-wide method / evidence-class success-rate trends
- `source_trends` — Federation-wide source-CATEGORY trends (effectiveness/trust/novelty; no source identities)
- `federation_consensus` — Advisory consensus confidence / disagreement / diversity / federation confidence (one capability or full report)
- `ecosystem_opportunities` — Advisory marketplace: capabilities popular elsewhere but missing locally, popular plugins, underrepresented categories
- `federation_health` — Federation-wide health: contributing peers, ecosystem/verification effectiveness, registry trust + mean federation confidence

### Temporal Knowledge Intelligence (Phase O — derived, advisory, deterministic)
A fully derived, offline-first temporal layer (`hydra/temporal_intel/`) that understands how
Hydra's knowledge EVOLVES over time — trends, momentum, decay, emerging/declining areas, bounded
forecasts, and temporal anomalies. Built ENTIRELY from the existing derived event logs
(source/verification/tool-health/plugin-health/decision/federation) via a load-once
`TemporalContext` (O(E), no repeated scans). A `TemporalStore` (`data/temporal.db`, WAL,
event-sourced, idempotent, rebuildable) persists observations/snapshots. `TrendAnalyzer`,
`MomentumAnalyzer`, `TemporalForecastEngine` (moving-average + linear slope, bounded,
NON-stochastic), `DecayAnalyzer` (advisory `TemporalDecayFinding`s), `TemporalAnomalyDetector`
(spike/drop/inactivity/concentration), `TemporalAdvisor` (bounded recommendations) and
`TemporalIntelligence` compose the views. Phase-J `governance_summary` gains a read-only
`temporal_intelligence` block (lazy import, no cycle). Deterministic (injected `now`),
rebuild-identical, advisory only; NO execution, NO wiki mutation, promotion.py/confidence.py
untouched. This is a NEW package — it does not reuse/modify the legacy `hydra/temporal/` subsystem.
- `temporal_summary` — Overview: temporal-health, strongest/weakest trends, emerging/declining capabilities, decay & anomaly counts, recommendations
- `temporal_trends` — Rising/stable/declining + momentum per entity (capability/adapter/agent/plugin/source/verification) with slope and bucket series
- `temporal_forecast` — Deterministic bounded forecasts: capability utilization, verification coverage, source diversity, plugin adoption
- `temporal_decay` — Stale capabilities/adapters/plugins/verification methods ranked by severity with rationale + suggested action
- `temporal_anomalies` — Spikes, drops, inactivity and concentration across domains (advisory findings; no alerts)
- `temporal_health` — 0-100 temporal-health score (rewards rising/active knowledge, penalizes decay + anomalies)

### Offensive Capability Intelligence (Phase P — derived, advisory, NON-executing)
A fully derived, offline-first offensive-intelligence layer (`hydra/offensive_intel/`) that scores the
EFFECTIVENESS, COVERAGE, composition, OVERLAP and ATTACK-PATH value of capabilities, workflows, agents,
plugins and skills — built from the existing derived learning logs (tool-health / verification) plus the
static declarative catalogs (effective capabilities, dependency graph, adapters, agent ownership, skills)
via a load-once `OffensiveContext` (O(E)). Cold-start falls back to the catalog `confidence_weight`
priors. Deterministic (injected `now`), rebuild-identical, advisory only; **NON-executing** — it SCORES
and ADVISES over the capability/skill MODEL and never exploits, validates, confirms, promotes, or
executes. Phase-J `governance_summary` gains a read-only `offensive_intelligence` block.
promotion.py/confidence.py and the canonical wiki are untouched.
- `offensive_summary` — Overview: offensive-health, top/underutilized capabilities, strongest chains, weak categories, redundant pairs, skill bridge, recommendations
- `offensive_effectiveness` — Per-capability effectiveness/utility/contribution/uniqueness/redundancy (+ explain); ranked or single capability
- `offensive_coverage` — Category / workflow (agent) / attack-path coverage
- `offensive_chains` — Capability attack chains scored by effectiveness/diversity/popularity (bounded, NON-executing)
- `offensive_overlap` — Redundant capability pairs + clusters (interchangeable capabilities)
- `offensive_gaps` — Weak categories, weakly-covered finding types, weak chains
- `offensive_skills` — Capability→Skill→Workflow→Agent bridge with skill effectiveness/quality
- `offensive_health` — 0-100 offensive-health score (effectiveness + structural coverage quality; advisory)

### Offensive Campaign Reasoning Engine (Phase Q — derived, advisory, NON-executing)
A store-free, offline-first campaign-reasoning layer (`hydra/campaigns/`) that lifts Hydra from capability
intelligence to CAMPAIGN-level reasoning: attack objectives, the 12 attack-tactic phases, capability
sequencing, skill composition, attack-path generation, gaps, and alternative strategies. Built over ONE shared
`CampaignContext` that reuses the Phase-P `OffensiveIntelligence` (load-once). **Skills are first-class** — a
campaign is explainable as BOTH a Capability Graph and a Skill Graph, and every generated campaign exposes
`campaign_capabilities` / `campaign_skills` / `campaign_agents` / `campaign_dependencies`. Deterministic
(injected `now`), rebuild-identical, advisory only; **NON-executing** — it reasons about campaign STRUCTURE and
never executes, touches targets, launches tools, confirms findings, or modifies promotion/confidence.
**Post-exploitation guard:** persistence / privilege_escalation / defense_evasion / lateral_movement /
collection / exfiltration are **model-only** (`hydra_capability_coverage = none`, `advisory_model_only = true`).
Phase-J `governance_summary` gains a read-only `campaign_intelligence` block. promotion.py/confidence.py and the
canonical wiki are untouched.
- `campaign_summary` — Overview: campaign-health, 12-phase model, workflow graph, playbooks, objectives, recommendations
- `campaign_objectives` — Objective → Skills → Capabilities → Adapters → Agents (explainable chains)
- `campaign_playbooks` — Scored playbooks; a single playbook exposes the 4 campaign facets + dual graphs
- `campaign_paths` — Per-playbook execution-order sequence + dual graphs, or bounded attack chains (NON-executing)
- `campaign_strategies` — Compare two strategies on coverage / diversity / effectiveness / dependency-risk / redundancy
- `campaign_simulation` — Counterfactual impact (remove capability/plugin, verification drop, category change); NON-executing
- `campaign_gaps` — Weak campaign phases + offensive gaps; model-only phases listed explicitly
- `campaign_health` — 0-100 campaign-health score (phase + playbook effectiveness + coverage; advisory)

### Skill Composition & Skill Graph Intelligence (Phase R — derived, advisory, NON-executing)
A store-free, offline-first skill-intelligence layer (`hydra/skill_intel/`) that promotes Skills into
first-class architecture entities: a **skill dependency graph** (derived from the capability dependency
graph, since declarative `chain_to` is unpopulated), a **skill composition graph** (shared capabilities),
**skill bundles**, per-skill effectiveness, skill coverage, skill gaps, and an advisory skill marketplace.
Built over ONE `SkillContext` that reuses the Phase-P `OffensiveIntelligence` (load-once). This is a NEW
package — it does **not** modify the legacy `hydra/skills/` operational subsystem; it only reads skills
(through the Phase-P skill bridge). Deterministic (injected `now`), rebuild-identical, advisory only;
**NON-executing** — skills never execute, never modify capability/promotion/confidence state, never create
runtime actions, and never become a canonical source. Phase-J `governance_summary` gains a read-only
`skill_intelligence` block. promotion.py/confidence.py and the canonical wiki are untouched.
- `skill_summary` — Overview: skill-health, graph stats, top skills, bundles, coverage, critical skills, gaps, recommendations
- `skill_graph` — Skill dependency graph (derived from the capability graph) + composition graph + clusters
- `skill_dependencies` — Dependency edges, critical skills (most depended-upon), isolated skills, cycles
- `skill_bundles` — Coherent skill bundles (by category) with union capabilities/agents + effectiveness
- `skill_effectiveness` — Per-skill effectiveness/utility/uniqueness/redundancy; ranked or single skill
- `skill_coverage` — Per-category skill coverage + overall capability coverage
- `skill_gaps` — Capabilities with no skill, weak skills, broken chain_to references
- `skill_marketplace` — Advisory: low-coverage categories + weak skills to strengthen (authors nothing)

### Opportunity Intelligence (Phase S — derived, advisory, NON-executing)
A store-free, offline-first opportunity-intelligence layer (`hydra/opportunity_intel/`) that identifies
**WHERE** Hydra's highest-value, least-covered, most-leveraged offensive **opportunities** are. Built over
ONE `OpportunityContext` that reuses the Phase-P `OffensiveIntelligence` (load-once) and threads that SAME
instance into the Phase-Q `CampaignIntelligence` and Phase-R `SkillGraphIntelligence` (no duplicate scans),
with bounded cross-store signals from the Phase-O temporal layer (emerging capabilities) and the Phase-N
federation layer (peer demand). Composes an **attack-surface model** (Hydra's own modelled reach — NOT a
live target), a **fused coverage synthesizer** (effectiveness/verification/exercise/agent/skill →
`coverage_index`), a **blind-spot analyzer** (severity-ranked; post-exploitation model-only phases flagged
INTENTIONAL), an **opportunity graph** (capability↔finding-type + hub/bottleneck leverage), a versioned
**`OpportunityScore`** ranker (`value + coverage_deficit + chain_potential + uniqueness + novelty` + capped
temporal/federation bonuses, fully explainable), and a SAFE-verb advisor. Deterministic (injected `now`),
rebuild-identical, advisory only; **NON-executing** — it SCORES and ADVISES over the capability MODEL and
never exploits, validates, confirms, promotes, or executes. Distinct from the Phase-D `rank_opportunities`
(which ranks discovery candidates, not the capability model). Phase-J `governance_summary` gains a read-only
`opportunity_intelligence` block. promotion.py/confidence.py and the canonical wiki are untouched.
- `opportunity_summary` — Overview: opportunity-health, surface totals, top opportunities, coverage, blind spots, graph bottlenecks, recommendations
- `opportunity_surface` — Attack-surface model: Hydra's own modelled reach by category (addressable finding/target types, effectiveness, verification, exercised); NON-executing
- `opportunity_coverage` — Synthesized per-category `coverage_index` fused over effectiveness/verification/exercise/agent/skill dimensions + overall index
- `opportunity_blindspots` — Severity-ranked blind spots fused across layers; INTENTIONAL model-only campaign phases flagged (never a defect)
- `opportunity_graph` — Capability↔finding-type structure + dependency edges; hub capabilities (high leverage) + bottleneck finding-types (single-provider)
- `opportunity_ranking` — Versioned `OpportunityScore` per capability (explainable components); ranked or single capability
- `opportunity_advisor` — Bounded SAFE-verb recommendations (prioritize/strengthen/expand/diversify/investigate/improve); authors nothing
- `opportunity_health` — 0-100 opportunity-health score (synthesized coverage + surface breadth + realization + blind-spot health; advisory)

### Adversary & ATT&CK Intelligence (Phase T — derived, advisory, NON-executing)
A store-free, offline-first adversary-intelligence layer (`hydra/adversary_intel/`) that models Hydra's
offensive tradecraft coverage against **MITRE ATT&CK** and the adversary profiles it supports. Built over
ONE `AdversaryContext` that reuses the Phase-P `OffensiveIntelligence` (load-once) threaded through the
Phase-S `OpportunityIntelligence` (which itself reuses Phase-Q `CampaignIntelligence` + Phase-R
`SkillGraphIntelligence`), plus a bounded Phase-O temporal signal. A static, declarative **`AttackMapping`**
ties the 14 ATT&CK Enterprise tactics + a curated technique set onto Hydra's real capability categories;
technique coverage is scored from the Phase-P effectiveness engine (`covered` / `weak` — incl.
single-provider **fragile** coverage / `uncovered` / `model_only`). **Post-exploitation / out-of-scope
guard:** Resource Development, Execution, Persistence, Privilege Escalation, Defense Evasion, Lateral
Movement, Collection, Command and Control, Exfiltration and Impact are **MODEL-ONLY** (zero capabilities,
zero execution — never a defect). Composes tactic/technique coverage, a skill→technique and
capability→technique map, declarative adversary-profile support scoring, gap analysis (bridging Phase-Q
campaign phases + Phase-S opportunities), a SAFE-verb advisor, and a 0-100 health score. Deterministic
(injected `now`), rebuild-identical, advisory only; **NON-executing** — it SCORES and ADVISES over the
capability MODEL and never exploits, emulates, validates, confirms, promotes, or executes. Phase-J
`governance_summary` gains a read-only `adversary_intelligence` block. promotion.py/confidence.py and the
canonical wiki are untouched.
- `adversary_summary` — Overview: adversary-health, tactic coverage (covered vs model-only), technique status, best-supported profiles, gaps, top capabilities, recommendations
- `attack_tactics` — ATT&CK tactic coverage: per-tactic covered/weak/uncovered counts, coverage %, mean effectiveness; model-only tactics flagged
- `attack_techniques` — ATT&CK technique coverage: per-technique status + supporting capabilities + effectiveness; ranked, one technique, or by tactic
- `attack_gaps` — Weak/uncovered in-scope techniques, weak tactics, Phase-Q campaign phases lacking coverage, Phase-S opportunities that lift coverage most
- `attack_profiles` — Adversary-profile support scoring (external recon / web-app / cloud / credential / supply-chain / surface-mapper); ranked or single
- `attack_skills` — Skill → ATT&CK technique/tactic map (which Phase-R skills contribute to which techniques)
- `attack_capabilities` — Capability → ATT&CK technique map; strongest technique coverage (effectiveness × breadth), ranked
- `attack_health` — 0-100 adversary-health score (in-scope technique coverage + per-tactic coverage + covered-technique effectiveness; advisory)

### Threat Intelligence & Knowledge Fusion (Phase U — derived, advisory, NON-executing)
A store-free, offline-first **knowledge-fusion** layer (`hydra/threat_intel/`) that transforms Hydra from
"knowing capabilities" into "understanding evolving threats, adversaries, campaigns, techniques, skills,
opportunities and knowledge signals together" — by **reasoning over Hydra's existing knowledge graph**. It
does NOT execute, attack, or collect live intelligence. A **Threat** is keyed by an ATT&CK tactic and fuses
all seven reused layers — Federation (N), Temporal (O), Offensive (P), Campaign (Q), Skill (R), Opportunity
(S), Adversary (T) — over ONE shared `ThreatContext` (a single `OffensiveContext` load threaded through
Phase-T → S/Q/R, plus bounded guarded O and N signals; no duplicate scans). Builds a fully-explainable
**Threat→Campaign→Technique→Capability→Skill→Agent** graph (every edge carries a `reason` — no hidden
inference), deterministic threat clustering, temporal threat evolution (rising/declining/emerging),
threat↔opportunity / skill / campaign / adversary fusion, per-threat risk, and a versioned 0-100
`threat_health` (coverage + redundancy/resilience + diversity + opportunity gaps + temporal decay +
federation consensus). Post-exploitation / out-of-scope tactics are MODEL-ONLY threats (`out_of_scope`,
never a fixable risk). Deterministic (injected `now`), rebuild-identical, advisory only; **NON-executing**.
Phase-J `governance_summary` gains a read-only `threat_intelligence` block. promotion.py/confidence.py and
the canonical wiki are untouched.
- `threat_summary` — Overview: threat-health, in-scope vs model-only threats, highest-risk threats, fusion-graph size, clusters, evolution, broadest adversary profiles, recommendations
- `threat_graph` — The unified Threat→Campaign→Technique→Capability→Skill→Agent graph; every edge carries a reason; full graph or one threat's subgraph
- `threat_clusters` — Related threats grouped by shared backing capabilities (deterministic connected components) with shared capabilities/skills + explainable reason
- `threat_evolution` — Fuses Phase-O temporal momentum with Phase-T coverage → rising/declining/stable threats + emerging patterns; bounded, no over-prediction
- `threat_opportunities` — Threat↔opportunity fusion: most-exposed threats + the Phase-S opportunities that would close the most risk
- `threat_skills` — Threat↔skill fusion: most-critical skills, underrepresented skills, and skill gaps creating the largest threat exposure
- `threat_campaigns` — Threat↔campaign fusion: best-covered phases, weakest paths, and stages relying on fragile (single-provider) capability coverage
- `threat_health` — 0-100 threat-health score fusing coverage/resilience/diversity/opportunity-gaps/decay/federation-consensus; fully explainable; advisory

