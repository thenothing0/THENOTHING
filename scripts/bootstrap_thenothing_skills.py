"""One-shot generator for modular skills/*/SKILL.yaml (THENOTHING layout)."""
from __future__ import annotations

import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "skills"

SPECS: dict[str, dict] = {
    "recon": {
        "name": "Passive Recon Orchestration",
        "category": "recon",
        "triggers": ["new_target", "scope_confirmed"],
        "technologies": [],
        "objectives": ["map_surface", "minimize_noise"],
        "mcp_tools": ["check_tools", "subfinder_scan", "amass_enum", "httpx_probe", "gau_urls", "katana_crawl"],
    },
    "web": {
        "name": "Web Attack Surface Reasoning",
        "category": "web",
        "triggers": ["html_response", "forms", "cookies"],
        "technologies": ["generic"],
        "objectives": ["inventory_inputs", "map_auth_flows"],
        "mcp_tools": ["whatweb_detect", "katana_crawl", "httpx_probe", "nuclei_scan"],
    },
    "api": {
        "name": "REST API Top 10 Reasoning",
        "category": "api",
        "triggers": ["openapi", "json_api", "bearer_token"],
        "technologies": [],
        "objectives": ["test_object_authz", "rate_limit_behavior"],
        "mcp_tools": ["httpx_probe", "ffuf_fuzz", "nuclei_scan"],
    },
    "graphql": {
        "name": "GraphQL Attack Surface",
        "category": "graphql",
        "triggers": ["graphql_endpoint", "introspection_hint"],
        "technologies": ["GraphQL", "Apollo", "Hasura"],
        "objectives": ["depth_batching_analysis", "field_sensitivity_map"],
        "mcp_tools": ["httpx_probe", "ffuf_fuzz", "nuclei_scan"],
    },
    "oauth": {
        "name": "OAuth OIDC Abuse Patterns",
        "category": "auth",
        "triggers": ["oauth_callback", "authorization_code_flow"],
        "technologies": ["OAuth2", "OIDC", "Clerk", "Auth0"],
        "objectives": ["redirect_uri_matrix", "state_parameter_checks"],
        "mcp_tools": ["httpx_probe", "katana_crawl"],
    },
    "business_logic": {
        "name": "Business Logic Flaw Hunting",
        "category": "business_logic",
        "triggers": ["multi_step_checkout", "wallet_credits"],
        "technologies": [],
        "objectives": ["state_machine_abuse", "trust_boundary_tests"],
        "mcp_tools": ["httpx_probe", "ffuf_fuzz"],
    },
    "cloud": {
        "name": "Cloud Misconfiguration Reasoning",
        "category": "cloud",
        "triggers": ["aws_headers", "azure_frontdoor", "gcp_lb"],
        "technologies": ["AWS", "Azure", "GCP"],
        "objectives": ["metadata_paths", "public_storage_indicators"],
        "mcp_tools": ["httpx_probe", "nuclei_scan"],
    },
    "kubernetes": {
        "name": "Kubernetes Exposure Patterns",
        "category": "kubernetes",
        "triggers": ["k8s_api", "dashboard", "kubeconfig_leak"],
        "technologies": ["Kubernetes"],
        "objectives": ["rbac_paths", "exposed_control_plane"],
        "mcp_tools": ["nmap_scan", "httpx_probe", "nuclei_scan"],
    },
    "osint": {
        "name": "OSINT Correlation",
        "category": "osint",
        "triggers": ["domain_only", "program_recon_allowed"],
        "technologies": [],
        "objectives": ["weak_signal_fusion", "asset_discovery"],
        "mcp_tools": ["subfinder_scan", "gau_urls", "httpx_probe"],
    },
    "xss": {
        "name": "advanced_xss_hunting",
        "category": "web",
        "triggers": ["reflected_input", "dom_sink_detected", "unsafe_innerhtml"],
        "technologies": ["React", "Next.js", "Vue"],
        "objectives": ["identify_reflection", "infer_dom_execution", "generate_bypass_payloads"],
        "mcp_tools": ["katana_crawl", "httpx_probe", "dalfox", "gxss"],
    },
    "sqli": {
        "name": "SQL Injection Hypothesis Engine",
        "category": "web",
        "triggers": ["sql_error_banner", "numeric_id_params"],
        "technologies": ["MySQL", "PostgreSQL", "MSSQL"],
        "objectives": ["classify_error_vs_blind", "reduce_fp"],
        "mcp_tools": ["httpx_probe", "sqlmap", "nuclei_scan"],
    },
    "ssrf": {
        "name": "SSRF Chain Reasoning",
        "category": "web",
        "triggers": ["url_fetch_feature", "webhook", "import_url"],
        "technologies": [],
        "objectives": ["internal_host_map", "cloud_metadata_hypotheses"],
        "mcp_tools": ["httpx_probe", "nuclei_scan"],
    },
    "ssti": {
        "name": "SSTI Detection and Engine Fingerprinting",
        "category": "web",
        "triggers": ["template_echo", "math_expression_reflection"],
        "technologies": ["Jinja2", "Twig", "Freemarker"],
        "objectives": ["engine_id", "safe_proof_artifacts"],
        "mcp_tools": ["httpx_probe", "ffuf_fuzz"],
    },
    "deserialization": {
        "name": "Insecure Deserialization",
        "category": "web",
        "triggers": ["serialized_blob", "java_viewstate", "pickle"],
        "technologies": [],
        "objectives": ["format_identification", "gadget_chain_hypotheses"],
        "mcp_tools": ["httpx_probe", "nuclei_scan"],
    },
    "auth": {
        "name": "Authentication Session Reasoning",
        "category": "auth",
        "triggers": ["jwt_cookie", "session_rotation", "mfa_flow"],
        "technologies": [],
        "objectives": ["token_binding", "logout_invalidation"],
        "mcp_tools": ["httpx_probe", "nuclei_scan"],
    },
    "race_conditions": {
        "name": "Race and Concurrency Testing",
        "category": "web",
        "triggers": ["balance_transfer", "coupon_redeem", "seat_booking"],
        "technologies": [],
        "objectives": ["parallel_timing_windows", "idempotency_checks"],
        "mcp_tools": ["httpx_probe"],
    },
    "ai_security": {
        "name": "AI LLM and Agent Abuse Surface",
        "category": "ai_security",
        "triggers": ["llm_endpoint", "tool_use", "rag_pipeline"],
        "technologies": ["OpenAI", "Anthropic", "local_llm"],
        "objectives": ["prompt_injection_surface", "mcp_tool_policy_review"],
        "mcp_tools": ["httpx_probe", "nuclei_scan"],
    },
    "mobile": {
        "name": "Mobile Client Trust Boundaries",
        "category": "mobile",
        "triggers": ["mobile_api", "deeplink"],
        "technologies": ["Android", "iOS"],
        "objectives": ["storage_model", "cert_pinning_signals"],
        "mcp_tools": ["httpx_probe"],
    },
    "browser": {
        "name": "Browser Centric Exploit Chains",
        "category": "frontend",
        "triggers": ["postmessage", "webrtc", "service_worker"],
        "technologies": ["Chrome", "Firefox"],
        "objectives": ["origin_policy_review", "client_storage"],
        "mcp_tools": ["httpx_probe", "katana_crawl"],
    },
    "javascript": {
        "name": "JavaScript Bundle Intelligence",
        "category": "frontend",
        "triggers": ["spa", "webpack", "sourcemaps"],
        "technologies": ["React", "Next.js", "Vue"],
        "objectives": ["secret_leak_scan", "dangerous_sinks"],
        "mcp_tools": ["katana_crawl", "httpx_probe"],
    },
    "websocket": {
        "name": "WebSocket Policy Testing",
        "category": "frontend",
        "triggers": ["upgrade_header", "ws_wss"],
        "technologies": [],
        "objectives": ["auth_on_socket", "origin_checks"],
        "mcp_tools": ["httpx_probe"],
    },
    "cicd": {
        "name": "CI CD Exposure Reasoning",
        "category": "cicd",
        "triggers": ["github_actions", "jenkins", "gitlab_ci"],
        "technologies": [],
        "objectives": ["workflow_secret_exposure", "artifact_tamper_surface"],
        "mcp_tools": ["httpx_probe", "nuclei_scan"],
    },
    "containers": {
        "name": "Container and Image Supply Surface",
        "category": "kubernetes",
        "triggers": ["docker_registry", "k8s_manifest"],
        "technologies": ["Docker"],
        "objectives": ["socket_mounts", "privileged_flags"],
        "mcp_tools": ["nuclei_scan", "httpx_probe"],
    },
    "aws": {
        "name": "AWS Specific Escalation Hypotheses",
        "category": "cloud",
        "triggers": ["x_amz_headers", "s3_host_style"],
        "technologies": ["AWS"],
        "objectives": ["iam_metadata_paths", "public_bucket_indicators"],
        "mcp_tools": ["httpx_probe", "nuclei_scan"],
    },
    "azure": {
        "name": "Azure Specific Escalation Hypotheses",
        "category": "cloud",
        "triggers": ["azurewebsites", "managed_identity"],
        "technologies": ["Azure"],
        "objectives": ["imds_paths", "aad_misbinding"],
        "mcp_tools": ["httpx_probe", "nuclei_scan"],
    },
    "gcp": {
        "name": "GCP Specific Escalation Hypotheses",
        "category": "cloud",
        "triggers": ["appspot", "run_app", "gcp_metadata"],
        "technologies": ["GCP"],
        "objectives": ["metadata_headers", "sa_key_exposure"],
        "mcp_tools": ["httpx_probe", "nuclei_scan"],
    },
    "reporting": {
        "name": "Validation First Reporting",
        "category": "reporting",
        "triggers": ["finding_candidate", "triage_complete"],
        "technologies": [],
        "objectives": ["impact_story", "repro_minimization"],
        "mcp_tools": ["generate_report"],
    },
    "exploit_chains": {
        "name": "Exploit Chain Composer",
        "category": "exploit_chains",
        "triggers": ["multi_hop_signal", "ssrf_plus_cloud"],
        "technologies": [],
        "objectives": ["chain_pruning", "evidence_per_hop"],
        "mcp_tools": ["nuclei_scan", "httpx_probe"],
    },
    "validation": {
        "name": "False Positive Reduction",
        "category": "validation",
        "triggers": ["scanner_hit", "heuristic_alert"],
        "technologies": [],
        "objectives": ["independent_replay", "control_case"],
        "mcp_tools": ["httpx_probe", "nuclei_scan"],
    },
    "stealth": {
        "name": "Responsible Passive First Operations",
        "category": "stealth",
        "triggers": ["rate_limit_sensitive", "waf_detected"],
        "technologies": [],
        "objectives": ["throttle_mcp_calls", "prefer_passive_sources"],
        "mcp_tools": ["check_tools", "httpx_probe"],
    },
    "opsec": {
        "name": "Operator Safety and Data Handling",
        "category": "opsec",
        "triggers": ["pii_risk", "credential_artifacts"],
        "technologies": [],
        "objectives": ["minimize_sensitive_logs", "scope_recheck"],
        "mcp_tools": ["check_tools"],
    },
}


def render(folder: str, spec: dict) -> str:
    fid = f"tn_{folder}"
    body = {
        "id": fid,
        "name": spec["name"],
        "category": spec["category"],
        "version": "1.0",
        "severity": "high",
        "description": f"THENOTHING modular skill for /{folder}/ — authorized testing only.",
        "triggers": spec["triggers"],
        "technologies": spec["technologies"],
        "objectives": spec["objectives"],
        "reasoning_heuristics": [
            "Start from scope and program rules; refuse out-of-scope execution.",
            "Prefer correlated weak signals over single noisy scanner lines.",
            "Branch: if WAF or CDN detected, narrow active tests and increase validation rigor.",
        ],
        "exploit_hypotheses": [
            {
                "id": f"{fid}_h1",
                "title": "Contextual hypothesis",
                "description": "Derive a minimal test aligned with objectives; validate before reporting.",
                "test_steps": ["Map entrypoint", "Isolate variable", "Replay with control"],
                "severity": "medium",
                "confidence": 0.45,
            }
        ],
        "mcp_tools": spec["mcp_tools"],
        "stealth_mode": "adaptive",
        "validation": {"require_replay": True, "require_screenshot": False},
        "confidence_rules": {"minimum_score": 0.72},
        "false_positive_reduction": [
            "Require second independent signal (header + behavior, or tool + manual).",
            "Discard banner-only version claims without behavior proof.",
        ],
        "reporting_guidance": [
            "Impact, affected assets, reproduction, remediation, and safe harbor alignment.",
        ],
        "adaptive_branches": {"waf_detected": "reduce_active_fuzz", "api_heavy": "prioritize_api_skill_chain"},
        "chain_to": [],
        "references": ["https://owasp.org/www-project-top-ten/"],
    }
    import yaml  # noqa: PLC0415

    return yaml.dump(body, sort_keys=False, allow_unicode=True)


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    for folder, spec in SPECS.items():
        d = ROOT / folder
        d.mkdir(parents=True, exist_ok=True)
        (d / "SKILL.yaml").write_text(render(folder, spec), encoding="utf-8")
    (ROOT / "_schema.yaml").write_text(
        textwrap.dedent(
            """
            # THENOTHING modular skill schema (see hydra/skills/yaml_loader.py)
            required_concepts:
              - id
              - name
              - category
              - reasoning_heuristics
              - mcp_tools
            optional:
              - triggers
              - technologies
              - objectives
              - exploit_hypotheses
              - validation
              - stealth_mode
              - confidence_rules
              - adaptive_branches
              - false_positive_reduction
              - reporting_guidance
              - chain_to
              - references
            execution_rule: "All tool execution via MCP only; store artifacts under output/"
            """
        ).lstrip(),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
