"""
╔══════════════════════════════════════════════════════════════╗
║  Intelligence Packs System — Modular Attack Intelligence    ║
║  Hot-loadable, versioned, technology-specific attack packs  ║
║  Each pack: fingerprints, heuristics, workflows, exploits   ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path
from abc import ABC, abstractmethod

logger = logging.getLogger("hydra.packs")


# ──────────────────────────────────────────────
#  Pack Data Models
# ──────────────────────────────────────────────

@dataclass
class PackFingerprint:
    """Technology fingerprint within a pack."""
    name: str
    headers: Dict[str, str] = field(default_factory=dict)
    html_patterns: List[str] = field(default_factory=list)
    cookie_patterns: List[str] = field(default_factory=list)
    url_patterns: List[str] = field(default_factory=list)


@dataclass
class PackHeuristic:
    """Attack heuristic within a pack."""
    name: str
    description: str
    confidence: float = 0.5
    check_type: str = "http"  # http, header, path, response
    conditions: Dict[str, Any] = field(default_factory=dict)
    priority: int = 2


@dataclass
class PackExploitHypothesis:
    """Exploit hypothesis template."""
    name: str
    vuln_class: str
    description: str
    test_steps: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    severity: str = "medium"
    confidence: float = 0.5
    references: List[str] = field(default_factory=list)


@dataclass
class PackWorkflow:
    """Recon/attack workflow template."""
    name: str
    description: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    tools_required: List[str] = field(default_factory=list)
    estimated_duration: str = "5min"


@dataclass
class IntelligencePack:
    """Complete intelligence pack definition."""
    name: str
    version: str
    description: str
    author: str = "hydra"
    technology: str = ""
    category: str = ""  # web, cloud, api, mobile, auth
    fingerprints: List[PackFingerprint] = field(default_factory=list)
    heuristics: List[PackHeuristic] = field(default_factory=list)
    exploit_hypotheses: List[PackExploitHypothesis] = field(default_factory=list)
    recon_workflows: List[PackWorkflow] = field(default_factory=list)
    attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    nuclei_tags: List[str] = field(default_factory=list)
    signatures: List[Dict[str, Any]] = field(default_factory=list)
    validation_templates: List[Dict[str, Any]] = field(default_factory=list)
    reporting_templates: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    loaded_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)


# ──────────────────────────────────────────────
#  Built-in Intelligence Packs
# ──────────────────────────────────────────────

def _wordpress_pack() -> IntelligencePack:
    return IntelligencePack(
        name="wordpress", version="1.0.0",
        description="WordPress CMS security analysis pack",
        technology="WordPress", category="cms",
        fingerprints=[PackFingerprint(
            name="WordPress", html_patterns=["wp-content", "wp-includes", "wp-json"],
            cookie_patterns=["wordpress_", "wp-settings"],
        )],
        heuristics=[
            PackHeuristic(name="xmlrpc_exposed", description="WordPress XML-RPC exposed", confidence=0.8,
                          check_type="path", conditions={"path": "/xmlrpc.php", "expect_status": [200, 405]}),
            PackHeuristic(name="wp_json_exposed", description="WordPress REST API exposed", confidence=0.9,
                          check_type="path", conditions={"path": "/wp-json/wp/v2/users", "expect_status": [200]}),
            PackHeuristic(name="readme_exposed", description="WordPress readme.html exposed", confidence=0.6,
                          check_type="path", conditions={"path": "/readme.html", "expect_status": [200]}),
            PackHeuristic(name="debug_log", description="WordPress debug.log exposed", confidence=0.7,
                          check_type="path", conditions={"path": "/wp-content/debug.log", "expect_status": [200]}),
        ],
        exploit_hypotheses=[
            PackExploitHypothesis(
                name="wp_user_enum", vuln_class="information_disclosure",
                description="WordPress user enumeration via REST API",
                test_steps=["GET /wp-json/wp/v2/users", "Check for username disclosure"],
                severity="medium", confidence=0.8,
            ),
            PackExploitHypothesis(
                name="wp_xmlrpc_bruteforce", vuln_class="brute_force",
                description="WordPress XML-RPC authentication brute force",
                test_steps=["POST /xmlrpc.php with system.multicall", "Test credential stuffing"],
                severity="high", confidence=0.7,
            ),
            PackExploitHypothesis(
                name="wp_plugin_vuln", vuln_class="known_vulnerability",
                description="Known WordPress plugin vulnerabilities",
                test_steps=["Enumerate plugins via wp-content", "Check version against CVE database"],
                severity="high", confidence=0.6,
            ),
        ],
        recon_workflows=[PackWorkflow(
            name="wp_recon", description="WordPress reconnaissance workflow",
            steps=[
                {"tool": "httpx", "params": {"path": "/wp-json/wp/v2/users"}},
                {"tool": "nuclei", "params": {"tags": "wordpress", "severity": "medium,high,critical"}},
                {"tool": "ffuf", "params": {"wordlist": "wp-plugins.txt", "path": "/wp-content/plugins/FUZZ/readme.txt"}},
            ],
            tools_required=["httpx", "nuclei", "ffuf"],
        )],
        nuclei_tags=["wordpress", "wp-plugin", "wp-theme"],
        attack_chains=[{
            "name": "WP Full Compromise",
            "steps": ["user_enum", "xmlrpc_bruteforce", "admin_rce"],
            "impact": "critical",
        }],
    )


def _nextjs_pack() -> IntelligencePack:
    return IntelligencePack(
        name="nextjs", version="1.0.0",
        description="Next.js / Vercel security analysis pack",
        technology="Next.js", category="web",
        fingerprints=[PackFingerprint(
            name="Next.js", html_patterns=["__NEXT_DATA__", "_next/static"],
            headers={"x-nextjs-cache": "*", "x-vercel-id": "*"},
        )],
        heuristics=[
            PackHeuristic(name="nextjs_data_leak", description="__NEXT_DATA__ contains sensitive server props",
                          confidence=0.7, check_type="html", conditions={"pattern": "__NEXT_DATA__"}),
            PackHeuristic(name="api_routes_exposed", description="Next.js API routes enumeration",
                          confidence=0.8, check_type="path", conditions={"path": "/api/", "expect_status": [200, 404]}),
            PackHeuristic(name="source_maps", description="Next.js source maps exposed",
                          confidence=0.6, check_type="path", conditions={"path": "/_next/static/", "pattern": ".map"}),
        ],
        exploit_hypotheses=[
            PackExploitHypothesis(
                name="nextjs_ssrf", vuln_class="ssrf",
                description="Next.js API route SSRF via fetch/axios",
                test_steps=["Enumerate /api/ routes", "Test URL parameters for SSRF", "Check for internal resource access"],
                severity="high", confidence=0.6,
            ),
            PackExploitHypothesis(
                name="nextjs_auth_bypass", vuln_class="auth_bypass",
                description="Next.js middleware authentication bypass",
                test_steps=["Test edge middleware behavior", "Check for path traversal in routing",
                             "Test _next/data direct access"],
                severity="high", confidence=0.5,
            ),
            PackExploitHypothesis(
                name="nextjs_env_exposure", vuln_class="information_disclosure",
                description="Next.js environment variable exposure via __NEXT_DATA__",
                test_steps=["Parse __NEXT_DATA__ JSON", "Search for API keys, tokens, internal URLs"],
                severity="medium", confidence=0.7,
            ),
        ],
        recon_workflows=[PackWorkflow(
            name="nextjs_recon", description="Next.js application reconnaissance",
            steps=[
                {"action": "parse_next_data", "description": "Extract __NEXT_DATA__ from pages"},
                {"tool": "katana", "params": {"depth": "3"}},
                {"action": "enumerate_api_routes", "description": "Fuzz /api/ endpoints"},
                {"tool": "nuclei", "params": {"tags": "nextjs,react,javascript"}},
            ],
        )],
        nuclei_tags=["nextjs", "react", "javascript", "vercel"],
    )


def _graphql_pack() -> IntelligencePack:
    return IntelligencePack(
        name="graphql", version="1.0.0",
        description="GraphQL API security analysis pack",
        technology="GraphQL", category="api",
        heuristics=[
            PackHeuristic(name="introspection_enabled", description="GraphQL introspection query enabled",
                          confidence=0.9, check_type="http",
                          conditions={"method": "POST", "path": "/graphql",
                                      "body": '{"query":"{__schema{types{name}}}"}'}),
            PackHeuristic(name="graphiql_exposed", description="GraphiQL IDE exposed",
                          confidence=0.8, check_type="path", conditions={"path": "/graphiql"}),
        ],
        exploit_hypotheses=[
            PackExploitHypothesis(
                name="graphql_idor", vuln_class="idor",
                description="GraphQL IDOR via direct object reference in queries",
                test_steps=["Introspect schema", "Identify ID-based queries", "Test cross-user access"],
                severity="high", confidence=0.6,
            ),
            PackExploitHypothesis(
                name="graphql_injection", vuln_class="injection",
                description="GraphQL injection via unsanitized arguments",
                test_steps=["Test string arguments for SQLi", "Test filter arguments", "Check for NoSQL injection"],
                severity="high", confidence=0.5,
            ),
            PackExploitHypothesis(
                name="graphql_dos", vuln_class="dos",
                description="GraphQL denial of service via deep/circular queries",
                test_steps=["Test query depth limits", "Test nested fragment queries", "Check rate limiting"],
                severity="medium", confidence=0.7,
            ),
        ],
        nuclei_tags=["graphql", "api"],
    )


def _aws_pack() -> IntelligencePack:
    return IntelligencePack(
        name="aws", version="1.0.0",
        description="AWS cloud security analysis pack",
        technology="AWS", category="cloud",
        heuristics=[
            PackHeuristic(name="s3_bucket_exposed", description="Public S3 bucket detected",
                          confidence=0.8, check_type="http",
                          conditions={"url_pattern": r".*\.s3\.amazonaws\.com"}),
            PackHeuristic(name="metadata_endpoint", description="AWS metadata endpoint accessible",
                          confidence=0.9, check_type="http",
                          conditions={"url": "http://169.254.169.254/latest/meta-data/"}),
            PackHeuristic(name="cognito_pool", description="AWS Cognito user pool exposed",
                          confidence=0.7, check_type="html",
                          conditions={"pattern": "cognito-idp.*amazonaws.com"}),
        ],
        exploit_hypotheses=[
            PackExploitHypothesis(
                name="aws_ssrf_metadata", vuln_class="ssrf",
                description="SSRF to AWS metadata endpoint for credential theft",
                test_steps=["Find SSRF vector", "Access http://169.254.169.254/latest/meta-data/iam/",
                             "Extract temporary credentials"],
                severity="critical", confidence=0.5,
            ),
            PackExploitHypothesis(
                name="aws_s3_misconfiguration", vuln_class="misconfiguration",
                description="S3 bucket listing/write access",
                test_steps=["Test bucket listing", "Test PUT object", "Check ACL"],
                severity="high", confidence=0.7,
            ),
        ],
        nuclei_tags=["aws", "cloud", "s3", "ec2"],
    )


def _laravel_pack() -> IntelligencePack:
    return IntelligencePack(
        name="laravel", version="1.0.0",
        description="Laravel PHP framework security analysis pack",
        technology="Laravel", category="web",
        fingerprints=[PackFingerprint(
            name="Laravel", cookie_patterns=["laravel_session", "XSRF-TOKEN"],
            html_patterns=["laravel", "csrf-token"],
        )],
        heuristics=[
            PackHeuristic(name="debug_mode", description="Laravel debug mode enabled",
                          confidence=0.9, check_type="http",
                          conditions={"expect_error": True, "pattern": "Whoops"}),
            PackHeuristic(name="env_exposed", description="Laravel .env file exposed",
                          confidence=0.8, check_type="path", conditions={"path": "/.env", "expect_status": [200]}),
            PackHeuristic(name="telescope_exposed", description="Laravel Telescope exposed",
                          confidence=0.7, check_type="path", conditions={"path": "/telescope", "expect_status": [200, 302]}),
        ],
        exploit_hypotheses=[
            PackExploitHypothesis(
                name="laravel_debug_rce", vuln_class="rce",
                description="Laravel debug mode RCE via Ignition",
                test_steps=["Check debug mode", "Test CVE-2021-3129", "Attempt file write"],
                severity="critical", confidence=0.6,
                references=["CVE-2021-3129"],
            ),
            PackExploitHypothesis(
                name="laravel_deserialization", vuln_class="deserialization",
                description="Laravel unserialize vulnerability",
                test_steps=["Check for encrypted cookie manipulation", "Test APP_KEY leakage",
                             "Attempt deserialization payload"],
                severity="critical", confidence=0.5,
            ),
        ],
        nuclei_tags=["laravel", "php"],
    )


def _oauth_pack() -> IntelligencePack:
    return IntelligencePack(
        name="oauth", version="1.0.0",
        description="OAuth/OIDC authentication security analysis pack",
        technology="OAuth 2.0", category="auth",
        heuristics=[
            PackHeuristic(name="open_redirect", description="OAuth redirect_uri open redirect",
                          confidence=0.7, check_type="http",
                          conditions={"param": "redirect_uri", "test": "open_redirect"}),
        ],
        exploit_hypotheses=[
            PackExploitHypothesis(
                name="oauth_redirect_steal", vuln_class="open_redirect",
                description="OAuth authorization code theft via redirect_uri manipulation",
                test_steps=["Identify OAuth endpoints", "Test redirect_uri validation",
                             "Attempt code/token theft via open redirect"],
                severity="high", confidence=0.6,
            ),
            PackExploitHypothesis(
                name="oauth_state_bypass", vuln_class="csrf",
                description="OAuth CSRF via missing/weak state parameter",
                test_steps=["Check state parameter presence", "Test state randomness",
                             "Attempt cross-site request forgery"],
                severity="medium", confidence=0.7,
            ),
            PackExploitHypothesis(
                name="oauth_scope_escalation", vuln_class="privilege_escalation",
                description="OAuth scope escalation via parameter manipulation",
                test_steps=["Enumerate available scopes", "Test adding unauthorized scopes",
                             "Check scope enforcement on resource server"],
                severity="high", confidence=0.5,
            ),
        ],
        nuclei_tags=["oauth", "jwt", "auth"],
    )


def _kubernetes_pack() -> IntelligencePack:
    return IntelligencePack(
        name="kubernetes", version="1.0.0",
        description="Kubernetes security analysis pack",
        technology="Kubernetes", category="cloud",
        heuristics=[
            PackHeuristic(name="k8s_api_exposed", description="Kubernetes API server exposed",
                          confidence=0.9, check_type="path",
                          conditions={"path": "/api/v1/namespaces", "expect_status": [200, 401, 403]}),
            PackHeuristic(name="k8s_dashboard", description="Kubernetes dashboard exposed",
                          confidence=0.8, check_type="path",
                          conditions={"path": "/api/v1/namespaces/kubernetes-dashboard"}),
        ],
        exploit_hypotheses=[
            PackExploitHypothesis(
                name="k8s_unauth_api", vuln_class="auth_bypass",
                description="Unauthenticated Kubernetes API access",
                test_steps=["Test API access without credentials", "Enumerate namespaces",
                             "Check for privileged pods"],
                severity="critical", confidence=0.5,
            ),
        ],
        nuclei_tags=["kubernetes", "k8s", "cloud"],
    )


def _api_security_pack() -> IntelligencePack:
    return IntelligencePack(
        name="api_security", version="1.0.0",
        description="General API security analysis pack",
        technology="REST API", category="api",
        heuristics=[
            PackHeuristic(name="cors_misconfiguration", description="Permissive CORS policy",
                          confidence=0.7, check_type="header",
                          conditions={"header": "access-control-allow-origin", "value": "*"}),
            PackHeuristic(name="api_docs_exposed", description="API documentation publicly accessible",
                          confidence=0.6, check_type="path",
                          conditions={"paths": ["/swagger", "/api-docs", "/openapi.json", "/docs"]}),
        ],
        exploit_hypotheses=[
            PackExploitHypothesis(
                name="bola", vuln_class="idor",
                description="Broken Object Level Authorization (BOLA/IDOR)",
                test_steps=["Identify resource endpoints", "Test cross-user access", "Check ID enumeration"],
                severity="high", confidence=0.6,
            ),
            PackExploitHypothesis(
                name="mass_assignment", vuln_class="mass_assignment",
                description="Mass assignment via unprotected object properties",
                test_steps=["Identify writable endpoints", "Add extra properties (role, admin, isAdmin)",
                             "Check for privilege escalation"],
                severity="high", confidence=0.5,
            ),
            PackExploitHypothesis(
                name="rate_limiting_bypass", vuln_class="rate_limiting",
                description="API rate limiting bypass",
                test_steps=["Test rate limits", "Try bypass via headers (X-Forwarded-For)",
                             "Test different API versions"],
                severity="medium", confidence=0.7,
            ),
        ],
        nuclei_tags=["api", "rest", "json"],
    )


def _firebase_pack() -> IntelligencePack:
    return IntelligencePack(
        name="firebase", version="1.0.0",
        description="Firebase / Google Cloud security analysis pack",
        technology="Firebase", category="cloud",
        heuristics=[
            PackHeuristic(name="firebase_db_open", description="Firebase Realtime Database open read",
                          confidence=0.9, check_type="http",
                          conditions={"url_suffix": ".firebaseio.com/.json"}),
            PackHeuristic(name="firebase_storage_open", description="Firebase Storage bucket listing",
                          confidence=0.8, check_type="http",
                          conditions={"url_pattern": r"firebasestorage\.googleapis\.com"}),
        ],
        exploit_hypotheses=[
            PackExploitHypothesis(
                name="firebase_unauth_read", vuln_class="misconfiguration",
                description="Firebase database unauthenticated read access",
                test_steps=["GET /.json", "Check for sensitive data exposure"],
                severity="high", confidence=0.8,
            ),
            PackExploitHypothesis(
                name="firebase_unauth_write", vuln_class="misconfiguration",
                description="Firebase database unauthenticated write access",
                test_steps=["PUT /test.json", "Check write permissions"],
                severity="critical", confidence=0.7,
            ),
        ],
        nuclei_tags=["firebase", "google", "cloud"],
    )


def _supabase_pack() -> IntelligencePack:
    return IntelligencePack(
        name="supabase", version="1.0.0",
        description="Supabase security analysis pack",
        technology="Supabase", category="cloud",
        heuristics=[
            PackHeuristic(name="supabase_anon_key", description="Supabase anonymous key exposed",
                          confidence=0.7, check_type="html",
                          conditions={"pattern": "supabase.*anon.*key"}),
        ],
        exploit_hypotheses=[
            PackExploitHypothesis(
                name="supabase_rls_bypass", vuln_class="auth_bypass",
                description="Supabase Row Level Security bypass",
                test_steps=["Test RLS policies", "Check service role key exposure",
                             "Test direct PostgREST access"],
                severity="high", confidence=0.5,
            ),
        ],
        nuclei_tags=["supabase"],
    )


def _cloudflare_pack() -> IntelligencePack:
    return IntelligencePack(
        name="cloudflare", version="1.0.0",
        description="Cloudflare security analysis pack",
        technology="Cloudflare", category="cdn",
        heuristics=[
            PackHeuristic(name="origin_ip_leak", description="Origin IP address leakage behind Cloudflare",
                          confidence=0.6, check_type="dns",
                          conditions={"check": "historical_dns"}),
        ],
        exploit_hypotheses=[
            PackExploitHypothesis(
                name="cf_origin_bypass", vuln_class="waf_bypass",
                description="Cloudflare WAF bypass via direct origin access",
                test_steps=["Find origin IP via DNS history", "Test direct origin access",
                             "Compare WAF-filtered vs direct responses"],
                severity="medium", confidence=0.5,
            ),
        ],
        nuclei_tags=["cloudflare", "cdn"],
    )


# ──────────────────────────────────────────────
#  Pack Registry & Manager
# ──────────────────────────────────────────────

BUILTIN_PACKS: Dict[str, Callable[[], IntelligencePack]] = {
    "wordpress": _wordpress_pack,
    "nextjs": _nextjs_pack,
    "graphql": _graphql_pack,
    "aws": _aws_pack,
    "laravel": _laravel_pack,
    "oauth": _oauth_pack,
    "kubernetes": _kubernetes_pack,
    "api_security": _api_security_pack,
    "firebase": _firebase_pack,
    "supabase": _supabase_pack,
    "cloudflare": _cloudflare_pack,
}


class PackRegistry:
    """
    Intelligence Pack Registry.

    Hot-loadable, versioned, independently extendable.
    Packs are activated dynamically based on fingerprint results.
    """

    def __init__(self):
        self._packs: Dict[str, IntelligencePack] = {}
        self._active_packs: Dict[str, IntelligencePack] = {}
        self._load_builtins()

    def _load_builtins(self):
        """Load all built-in packs."""
        for name, factory in BUILTIN_PACKS.items():
            try:
                pack = factory()
                self._packs[name] = pack
            except Exception as e:
                logger.warning(f"Failed to load pack '{name}': {e}")
        logger.info(f"📦 Loaded {len(self._packs)} intelligence packs")

    def register(self, pack: IntelligencePack):
        """Register a custom intelligence pack."""
        self._packs[pack.name] = pack
        logger.info(f"📦 Registered pack: {pack.name} v{pack.version}")

    def load_from_file(self, path: str) -> Optional[IntelligencePack]:
        """Load a pack from a JSON file."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            pack = IntelligencePack(**data)
            self.register(pack)
            return pack
        except Exception as e:
            logger.error(f"Failed to load pack from {path}: {e}")
            return None

    def get_pack(self, name: str) -> Optional[IntelligencePack]:
        return self._packs.get(name)

    def list_packs(self) -> List[Dict[str, str]]:
        return [
            {"name": p.name, "version": p.version, "description": p.description,
             "category": p.category, "technology": p.technology}
            for p in self._packs.values()
        ]

    def activate_packs(self, triggers: List[str]) -> List[IntelligencePack]:
        """
        Activate packs based on technology fingerprint triggers.

        This is called by the Planner Agent after fingerprinting.
        """
        activated = []
        for trigger in triggers:
            trigger_lower = trigger.lower()
            if trigger_lower in self._packs:
                pack = self._packs[trigger_lower]
                self._active_packs[trigger_lower] = pack
                activated.append(pack)
                logger.info(f"⚡ Activated pack: {pack.name} v{pack.version}")

        # Always activate api_security if any API is detected
        if any(t in triggers for t in ["graphql", "rest", "api"]):
            if "api_security" not in self._active_packs and "api_security" in self._packs:
                self._active_packs["api_security"] = self._packs["api_security"]
                activated.append(self._packs["api_security"])

        return activated

    def get_active_packs(self) -> List[IntelligencePack]:
        return list(self._active_packs.values())

    def get_all_heuristics(self) -> List[PackHeuristic]:
        """Get all heuristics from active packs."""
        heuristics = []
        for pack in self._active_packs.values():
            heuristics.extend(pack.heuristics)
        return sorted(heuristics, key=lambda h: h.priority)

    def get_all_exploit_hypotheses(self) -> List[PackExploitHypothesis]:
        """Get all exploit hypotheses from active packs."""
        hypotheses = []
        for pack in self._active_packs.values():
            hypotheses.extend(pack.exploit_hypotheses)
        return hypotheses

    def get_all_nuclei_tags(self) -> List[str]:
        """Get all nuclei tags from active packs."""
        tags = set()
        for pack in self._active_packs.values():
            tags.update(pack.nuclei_tags)
        return sorted(tags)

    def get_all_workflows(self) -> List[PackWorkflow]:
        """Get all recon workflows from active packs."""
        workflows = []
        for pack in self._active_packs.values():
            workflows.extend(pack.recon_workflows)
        return workflows

    def get_all_attack_chains(self) -> List[Dict[str, Any]]:
        """Get all attack chains from active packs."""
        chains = []
        for pack in self._active_packs.values():
            chains.extend(pack.attack_chains)
        return chains

    def deactivate_all(self):
        """Deactivate all packs."""
        self._active_packs.clear()
