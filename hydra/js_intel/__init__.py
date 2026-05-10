"""
╔══════════════════════════════════════════════════════════════╗
║  JavaScript Intelligence Engine — Deep JS Analysis          ║
║  Endpoint extraction, source-map analysis, secret scanning, ║
║  API schema inference, webpack chunk analysis               ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("hydra.js_intel")


@dataclass
class JSEndpoint:
    """An API endpoint extracted from JavaScript."""
    path: str
    method: str = "GET"
    source_file: str = ""
    params: List[str] = field(default_factory=list)
    auth_required: bool = False
    confidence: float = 0.5


@dataclass
class JSSecret:
    """A secret or credential found in JavaScript."""
    secret_type: str
    value: str
    source_file: str = ""
    line: int = 0
    severity: str = "high"
    confidence: float = 0.7


@dataclass
class JSAnalysisResult:
    """Complete result of JS analysis."""
    target: str
    scripts_analyzed: int = 0
    endpoints: List[JSEndpoint] = field(default_factory=list)
    secrets: List[JSSecret] = field(default_factory=list)
    api_schemas: List[Dict[str, Any]] = field(default_factory=list)
    graphql_endpoints: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    webpack_chunks: List[str] = field(default_factory=list)
    internal_domains: List[str] = field(default_factory=list)
    hidden_routes: List[str] = field(default_factory=list)
    source_maps: List[str] = field(default_factory=list)


# ──────────────────────────────────────────────
#  Regex Patterns for JS Analysis
# ──────────────────────────────────────────────

ENDPOINT_PATTERNS = [
    # fetch/axios/XMLHttpRequest calls
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`"']([^`"']+)[`"']''', re.I),
    # URL string patterns (API paths)
    re.compile(r'''[`"'](/api/[a-zA-Z0-9/_\-{}:.]+)[`"']'''),
    re.compile(r'''[`"'](/v[1-9]/[a-zA-Z0-9/_\-{}:.]+)[`"']'''),
    re.compile(r'''[`"'](/graphql[a-zA-Z0-9/_\-]*)[`"']'''),
    # Route definitions (React Router, Express, Next.js)
    re.compile(r'''path\s*:\s*[`"']([^`"']+)[`"']'''),
    re.compile(r'''route\s*\(\s*[`"']([^`"']+)[`"']'''),
    # Webpack dynamic imports
    re.compile(r'''import\s*\(\s*[`"']([^`"']+)[`"']\s*\)'''),
]

METHOD_PATTERNS = [
    (re.compile(r'\.get\s*\('), "GET"),
    (re.compile(r'\.post\s*\('), "POST"),
    (re.compile(r'\.put\s*\('), "PUT"),
    (re.compile(r'\.delete\s*\('), "DELETE"),
    (re.compile(r'\.patch\s*\('), "PATCH"),
    (re.compile(r'method\s*:\s*["\']POST["\']', re.I), "POST"),
    (re.compile(r'method\s*:\s*["\']PUT["\']', re.I), "PUT"),
    (re.compile(r'method\s*:\s*["\']DELETE["\']', re.I), "DELETE"),
]

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret_key": re.compile(r'''(?:aws_secret|secret_key|AWS_SECRET)["\s:=]+["\']?([A-Za-z0-9/+=]{40})["\']?''', re.I),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    "firebase_key": re.compile(r'''(?:firebase|FIREBASE)[A-Za-z_]*["\s:=]+["\']?([A-Za-z0-9_\-]{20,})["\']?''', re.I),
    "github_token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
    "slack_token": re.compile(r'xox[bporas]-[A-Za-z0-9\-]{10,}'),
    "stripe_key": re.compile(r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}'),
    "jwt": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "api_key_generic": re.compile(r'''(?:api[_-]?key|apikey|api_secret|client_secret)["\s:=]+["\']?([A-Za-z0-9_\-]{16,})["\']?''', re.I),
    "database_url": re.compile(r'(?:postgres|mysql|mongodb|redis)://[^\s"\']+'),
    "supabase_key": re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    "basic_auth": re.compile(r'Basic\s+[A-Za-z0-9+/=]{10,}'),
    "bearer_token": re.compile(r'Bearer\s+[A-Za-z0-9_\-\.]{20,}'),
    "oauth_secret": re.compile(r'''(?:client_secret|oauth_secret)["\s:=]+["\']?([A-Za-z0-9_\-]{16,})["\']?''', re.I),
}

GRAPHQL_PATTERNS = [
    re.compile(r'''[`"'](/graphql[^`"']*)[`"']'''),
    re.compile(r'''(?:query|mutation|subscription)\s+\w+\s*(?:\([^)]*\))?\s*\{'''),
    re.compile(r'__schema|__type|introspectionQuery', re.I),
]

DOMAIN_PATTERN = re.compile(
    r'''[`"'](https?://[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?::\d+)?(?:/[^`"'\s]*)?)[`"']'''
)

INTERNAL_DOMAIN_INDICATORS = [
    "internal", "staging", "dev", "test", "local", "private",
    "admin", "backend", "api-internal", "intranet", "corp",
]

FRAMEWORK_PATTERNS = {
    "React": [re.compile(r'React\.createElement|ReactDOM|__REACT'), re.compile(r'_jsx|jsxRuntime')],
    "Vue.js": [re.compile(r'Vue\.component|__vue__|createApp')],
    "Angular": [re.compile(r'angular\.module|ng-app|@angular')],
    "Next.js": [re.compile(r'__NEXT_DATA__|_next/static|getServerSideProps')],
    "Nuxt.js": [re.compile(r'__NUXT__|_nuxt/')],
    "Svelte": [re.compile(r'__svelte|svelte/internal')],
    "Remix": [re.compile(r'__remixContext|remix-run')],
    "Express": [re.compile(r'express\(\)|app\.listen|router\.get')],
    "jQuery": [re.compile(r'jQuery|\\$\(document\)')],
    "Webpack": [re.compile(r'webpackChunk|__webpack_require__')],
    "Vite": [re.compile(r'/@vite/|import\.meta\.hot')],
}


class JavaScriptIntelligenceEngine:
    """
    Advanced JavaScript analysis engine.

    Capabilities:
      - Endpoint extraction from JS bundles
      - Source-map analysis
      - Secret/credential scanning (15+ patterns)
      - API schema inference
      - GraphQL endpoint discovery
      - Hidden route discovery
      - Frontend framework detection
      - Webpack chunk analysis
      - Internal domain leakage
      - React/Vue/Next.js intelligence
    """

    def __init__(self):
        self._analyzed: Set[str] = set()

    def analyze_source(self, source: str, source_url: str = "") -> JSAnalysisResult:
        """Analyze a single JavaScript source string."""
        result = JSAnalysisResult(target=source_url)
        result.scripts_analyzed = 1

        self._extract_endpoints(source, source_url, result)
        self._extract_secrets(source, source_url, result)
        self._detect_graphql(source, source_url, result)
        self._detect_frameworks(source, result)
        self._extract_domains(source, result)
        self._detect_webpack(source, result)
        self._extract_routes(source, result)

        return result

    def analyze_multiple(self, sources: List[Tuple[str, str]]) -> JSAnalysisResult:
        """Analyze multiple JS sources and merge results."""
        merged = JSAnalysisResult(target="merged")
        seen_endpoints: Set[str] = set()
        seen_secrets: Set[str] = set()

        for source_code, source_url in sources:
            if source_url in self._analyzed:
                continue
            self._analyzed.add(source_url)

            partial = self.analyze_source(source_code, source_url)
            merged.scripts_analyzed += 1

            for ep in partial.endpoints:
                key = f"{ep.method}:{ep.path}"
                if key not in seen_endpoints:
                    seen_endpoints.add(key)
                    merged.endpoints.append(ep)

            for secret in partial.secrets:
                key = f"{secret.secret_type}:{secret.value[:20]}"
                if key not in seen_secrets:
                    seen_secrets.add(key)
                    merged.secrets.append(secret)

            merged.graphql_endpoints.extend(partial.graphql_endpoints)
            merged.internal_domains.extend(partial.internal_domains)
            merged.hidden_routes.extend(partial.hidden_routes)
            merged.source_maps.extend(partial.source_maps)
            for fw in partial.frameworks:
                if fw not in merged.frameworks:
                    merged.frameworks.append(fw)

        # Deduplicate
        merged.graphql_endpoints = list(set(merged.graphql_endpoints))
        merged.internal_domains = list(set(merged.internal_domains))
        merged.hidden_routes = list(set(merged.hidden_routes))

        return merged

    def _extract_endpoints(self, source: str, source_url: str, result: JSAnalysisResult):
        """Extract API endpoints from JS source."""
        for pattern in ENDPOINT_PATTERNS:
            matches = pattern.findall(source)
            for match in matches:
                path = match.strip()
                if not path or len(path) < 2 or path.startswith("//"):
                    continue
                if any(ext in path for ext in [".css", ".png", ".jpg", ".svg", ".ico", ".woff"]):
                    continue

                # Detect HTTP method from context
                method = "GET"
                # Search nearby context for method hints
                idx = source.find(path)
                if idx > 0:
                    ctx = source[max(0, idx - 100):idx]
                    for meth_pattern, meth in METHOD_PATTERNS:
                        if meth_pattern.search(ctx):
                            method = meth
                            break

                # Detect auth requirement
                auth = any(kw in source[max(0, idx - 200):idx + 200]
                           for kw in ["Authorization", "Bearer", "token", "auth", "jwt"])

                # Extract path params
                params = re.findall(r'\{(\w+)\}|:(\w+)', path)
                param_names = [p[0] or p[1] for p in params]

                result.endpoints.append(JSEndpoint(
                    path=path, method=method, source_file=source_url,
                    params=param_names, auth_required=auth,
                    confidence=0.7 if path.startswith("/api/") else 0.5,
                ))

    def _extract_secrets(self, source: str, source_url: str, result: JSAnalysisResult):
        """Scan for secrets and credentials."""
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(source)
            for match in matches[:5]:
                value = match if isinstance(match, str) else match[0] if match else ""
                if not value or len(value) < 8:
                    continue
                # Skip common false positives
                if value in ("undefined", "null", "true", "false"):
                    continue
                result.secrets.append(JSSecret(
                    secret_type=secret_type,
                    value=value[:60],
                    source_file=source_url,
                    severity="critical" if secret_type in ("aws_access_key", "private_key") else "high",
                    confidence=0.8 if secret_type in ("aws_access_key", "github_token", "stripe_key") else 0.6,
                ))

    def _detect_graphql(self, source: str, source_url: str, result: JSAnalysisResult):
        """Detect GraphQL endpoints and queries."""
        for pattern in GRAPHQL_PATTERNS:
            matches = pattern.findall(source)
            for match in matches:
                if match.startswith("/"):
                    result.graphql_endpoints.append(match)

    def _detect_frameworks(self, source: str, result: JSAnalysisResult):
        """Detect frontend frameworks."""
        for framework, patterns in FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(source):
                    if framework not in result.frameworks:
                        result.frameworks.append(framework)
                    break

    def _extract_domains(self, source: str, result: JSAnalysisResult):
        """Extract internal/staging domains."""
        matches = DOMAIN_PATTERN.findall(source)
        for url in matches:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            if any(ind in hostname.lower() for ind in INTERNAL_DOMAIN_INDICATORS):
                result.internal_domains.append(url)

    def _detect_webpack(self, source: str, result: JSAnalysisResult):
        """Detect webpack chunks and source maps."""
        # Source map references
        map_refs = re.findall(r'//[#@]\s*sourceMappingURL=(\S+)', source)
        result.source_maps.extend(map_refs)

        # Webpack chunk names
        chunks = re.findall(r'webpackChunk[A-Za-z_]*\s*\.\s*push\s*\(\s*\[\s*\[([^\]]+)\]', source)
        result.webpack_chunks.extend(chunks)

    def _extract_routes(self, source: str, result: JSAnalysisResult):
        """Extract client-side routes (React Router, Next.js, etc.)."""
        route_patterns = [
            re.compile(r'''<Route[^>]+path=["']([^"']+)["']'''),
            re.compile(r'''path:\s*["']([^"']+)["']'''),
            re.compile(r'''navigate\s*\(\s*["']([^"']+)["']'''),
            re.compile(r'''router\.push\s*\(\s*["']([^"']+)["']'''),
            re.compile(r'''Link\s+(?:href|to)=["']([^"']+)["']'''),
        ]
        for pattern in route_patterns:
            matches = pattern.findall(source)
            for route in matches:
                if route not in result.hidden_routes and route.startswith("/"):
                    result.hidden_routes.append(route)

    def get_summary(self) -> Dict[str, Any]:
        return {"scripts_analyzed": len(self._analyzed)}
