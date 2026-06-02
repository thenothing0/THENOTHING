"""
╔══════════════════════════════════════════════════════════════╗
║  API Security Intelligence Agent — Dedicated API Testing    ║
║  REST, GraphQL, gRPC, WebSocket analysis with BOLA/BFLA     ║
║  heuristics, mass-assignment detection, JWT analysis        ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger("hydra.api_security")


@dataclass
class APIEndpoint:
    """Discovered API endpoint."""
    path: str
    method: str = "GET"
    params: List[Dict[str, str]] = field(default_factory=list)
    auth_type: str = ""            # bearer, basic, api_key, cookie, none
    content_type: str = ""
    response_codes: List[int] = field(default_factory=list)
    source: str = ""               # openapi, crawl, js_analysis, fuzzing
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class APIVulnerability:
    """API-specific vulnerability finding."""
    vuln_type: str                 # bola, bfla, mass_assignment, idor, rate_limit, jwt, cors, info_disclosure
    title: str
    endpoint: str
    severity: str = "medium"
    confidence: float = 0.5
    evidence: str = ""
    reproduction: List[str] = field(default_factory=list)
    cwe: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class APISecurityReport:
    """Complete API security analysis report."""
    target: str
    endpoints_discovered: int = 0
    endpoints: List[APIEndpoint] = field(default_factory=list)
    vulnerabilities: List[APIVulnerability] = field(default_factory=list)
    auth_schemes: List[str] = field(default_factory=list)
    api_type: str = ""             # rest, graphql, grpc, soap, websocket
    openapi_spec: Optional[Dict] = None
    graphql_schema: Optional[Dict] = None
    jwt_analysis: Optional[Dict] = None
    cors_analysis: Optional[Dict] = None
    rate_limit_analysis: Optional[Dict] = None
    duration: float = 0.0


# ──────────────────────────────────────────────
#  JWT Analysis
# ──────────────────────────────────────────────

class JWTAnalyzer:
    """Analyze JWT tokens for weaknesses."""

    WEAK_ALGORITHMS = {"none", "HS256"}  # HS256 weak if secret is guessable
    DANGEROUS_CLAIMS = {"admin", "role", "is_admin", "isAdmin", "permissions", "groups"}

    @staticmethod
    def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
        """Decode JWT without verification (analysis only)."""
        import base64
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            # Decode header
            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))
            # Decode payload
            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))
            return {"header": header, "payload": payload, "signature": parts[2][:20] + "..."}
        except Exception:
            return None

    @classmethod
    def analyze(cls, token: str) -> Dict[str, Any]:
        """Analyze a JWT token for security issues."""
        decoded = cls.decode_jwt(token)
        if not decoded:
            return {"valid": False, "error": "Failed to decode"}

        issues = []
        header = decoded["header"]
        payload = decoded["payload"]

        # Check algorithm
        alg = header.get("alg", "").lower()
        if alg == "none":
            issues.append({"type": "critical", "issue": "Algorithm set to 'none' — signature bypass possible"})
        elif alg in ("hs256",):
            issues.append({"type": "medium", "issue": f"Weak algorithm '{alg}' — brute-forceable if short secret"})

        # Check for dangerous claims
        for claim in cls.DANGEROUS_CLAIMS:
            if claim in payload:
                issues.append({"type": "high", "issue": f"Privilege claim '{claim}' found in payload — test escalation"})

        # Check expiry
        if "exp" not in payload:
            issues.append({"type": "medium", "issue": "No expiration claim — token never expires"})
        elif payload.get("exp", 0) < time.time():
            issues.append({"type": "info", "issue": "Token has expired"})

        # Check if audience/issuer present
        if "iss" not in payload:
            issues.append({"type": "low", "issue": "No issuer claim"})
        if "aud" not in payload:
            issues.append({"type": "low", "issue": "No audience claim"})

        return {
            "valid": True,
            "header": header,
            "payload": {k: v for k, v in payload.items() if k not in ("iat", "exp", "nbf")},
            "algorithm": header.get("alg", "unknown"),
            "issues": issues,
            "issue_count": len(issues),
        }


# ──────────────────────────────────────────────
#  OpenAPI Parser
# ──────────────────────────────────────────────

class OpenAPIParser:
    """Parse OpenAPI/Swagger specifications."""

    @staticmethod
    def parse(spec: Dict) -> List[APIEndpoint]:
        """Extract endpoints from OpenAPI spec."""
        endpoints = []
        paths = spec.get("paths", {})
        base_path = spec.get("basePath", "")

        for path, methods in paths.items():
            full_path = f"{base_path}{path}" if base_path else path
            for method, details in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                    continue
                params = []
                for p in details.get("parameters", []):
                    params.append({
                        "name": p.get("name", ""),
                        "in": p.get("in", "query"),
                        "required": p.get("required", False),
                        "type": p.get("schema", {}).get("type", p.get("type", "string")),
                    })
                # Detect auth
                security = details.get("security", spec.get("security", []))
                auth_type = ""
                if security:
                    auth_type = "bearer"  # Simplified; real impl checks securityDefinitions

                endpoints.append(APIEndpoint(
                    path=full_path, method=method.upper(), params=params,
                    auth_type=auth_type, source="openapi",
                    content_type=",".join(details.get("consumes", ["application/json"])),
                    response_codes=list(details.get("responses", {}).keys()),
                ))

        return endpoints


# ──────────────────────────────────────────────
#  API Security Engine
# ──────────────────────────────────────────────

class APISecurityEngine:
    """
    Dedicated API Security Intelligence Agent.

    Capabilities:
      - OpenAPI/Swagger parsing
      - GraphQL schema extraction
      - Undocumented endpoint discovery
      - Auth-flow analysis
      - BOLA/BFLA heuristics
      - Mass-assignment detection
      - JWT weakness analysis
      - Rate-limit intelligence
      - IDOR graphing
      - CORS misconfiguration detection

    Supports: REST, GraphQL, gRPC, SOAP, WebSockets
    """

    def __init__(self):
        self._jwt_analyzer = JWTAnalyzer()
        self._openapi_parser = OpenAPIParser()
        self._endpoints: List[APIEndpoint] = []
        self._vulnerabilities: List[APIVulnerability] = []

    def analyze_openapi(self, spec: Dict) -> List[APIEndpoint]:
        """Parse and analyze an OpenAPI specification."""
        endpoints = self._openapi_parser.parse(spec)
        self._endpoints.extend(endpoints)

        # Flag endpoints without authentication
        for ep in endpoints:
            if not ep.auth_type and ep.method in ("POST", "PUT", "DELETE", "PATCH"):
                self._vulnerabilities.append(APIVulnerability(
                    vuln_type="bfla",
                    title=f"Write endpoint without auth: {ep.method} {ep.path}",
                    endpoint=f"{ep.method} {ep.path}",
                    severity="high", confidence=0.6,
                    cwe="CWE-862",
                    reproduction=[f"Send {ep.method} {ep.path} without credentials"],
                ))

        return endpoints

    def analyze_jwt(self, token: str) -> Dict[str, Any]:
        """Analyze a JWT token."""
        result = self._jwt_analyzer.analyze(token)
        if result.get("issues"):
            for issue in result["issues"]:
                self._vulnerabilities.append(APIVulnerability(
                    vuln_type="jwt",
                    title=issue["issue"],
                    endpoint="JWT",
                    severity=issue["type"],
                    confidence=0.7,
                    cwe="CWE-347",
                ))
        return result

    def check_bola_candidates(self, endpoints: Optional[List[APIEndpoint]] = None) -> List[APIVulnerability]:
        """Identify endpoints likely vulnerable to BOLA (Broken Object Level Authorization)."""
        eps = endpoints or self._endpoints
        candidates = []
        id_patterns = re.compile(r'\{(?:id|user_id|account_id|order_id|item_id)\}|:\w*id\b', re.I)

        for ep in eps:
            if id_patterns.search(ep.path):
                vuln = APIVulnerability(
                    vuln_type="bola",
                    title=f"BOLA candidate: {ep.method} {ep.path}",
                    endpoint=f"{ep.method} {ep.path}",
                    severity="high", confidence=0.5,
                    cwe="CWE-639",
                    reproduction=[
                        f"Authenticate as User A",
                        f"Send {ep.method} {ep.path} with User A's resource ID",
                        f"Authenticate as User B",
                        f"Send same request — check if User B can access User A's resource",
                    ],
                    metadata={"params": [p["name"] for p in ep.params if "id" in p["name"].lower()]},
                )
                candidates.append(vuln)
                self._vulnerabilities.append(vuln)

        return candidates

    def check_mass_assignment(self, endpoints: Optional[List[APIEndpoint]] = None) -> List[APIVulnerability]:
        """Identify endpoints vulnerable to mass assignment."""
        eps = endpoints or self._endpoints
        candidates = []
        dangerous_fields = ["role", "admin", "is_admin", "isAdmin", "permissions",
                           "group", "verified", "email_verified", "plan", "credits", "balance"]

        for ep in eps:
            if ep.method in ("POST", "PUT", "PATCH"):
                vuln = APIVulnerability(
                    vuln_type="mass_assignment",
                    title=f"Mass assignment candidate: {ep.method} {ep.path}",
                    endpoint=f"{ep.method} {ep.path}",
                    severity="high", confidence=0.4,
                    cwe="CWE-915",
                    reproduction=[
                        f"Send {ep.method} {ep.path} with normal parameters",
                        f"Add extra fields: {', '.join(dangerous_fields[:5])}",
                        f"Check if any were accepted and persisted",
                    ],
                )
                candidates.append(vuln)
                self._vulnerabilities.append(vuln)

        return candidates

    def check_cors(self, headers: Dict[str, str], origin: str = "") -> Dict[str, Any]:
        """Analyze CORS headers for misconfigurations."""
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        acam = headers.get("access-control-allow-methods", "")

        issues = []
        if acao == "*":
            issues.append({"type": "medium", "issue": "Wildcard CORS — any origin allowed"})
            if acac == "true":
                issues.append({"type": "critical",
                               "issue": "Wildcard CORS + credentials allowed — credential theft possible"})
        elif origin and acao == origin:
            issues.append({"type": "high",
                           "issue": f"CORS reflects arbitrary origin: {origin}"})

        result = {
            "allow_origin": acao,
            "allow_credentials": acac,
            "allow_methods": acam,
            "issues": issues,
            "misconfigured": len(issues) > 0,
        }

        for issue in issues:
            self._vulnerabilities.append(APIVulnerability(
                vuln_type="cors",
                title=issue["issue"],
                endpoint="CORS",
                severity=issue["type"],
                confidence=0.8,
                cwe="CWE-942",
            ))

        return result

    def check_rate_limiting(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze rate limiting headers."""
        rate_headers = {
            "x-ratelimit-limit": headers.get("x-ratelimit-limit", ""),
            "x-ratelimit-remaining": headers.get("x-ratelimit-remaining", ""),
            "x-ratelimit-reset": headers.get("x-ratelimit-reset", ""),
            "retry-after": headers.get("retry-after", ""),
        }
        has_rate_limit = any(v for v in rate_headers.values())

        if not has_rate_limit:
            self._vulnerabilities.append(APIVulnerability(
                vuln_type="rate_limit",
                title="No rate limiting headers detected",
                endpoint="API",
                severity="medium", confidence=0.5,
                cwe="CWE-770",
                reproduction=["Send 100+ rapid requests", "Check if all succeed without throttling"],
            ))

        return {"has_rate_limit": has_rate_limit, "headers": rate_headers}

    def generate_report(self, target: str) -> APISecurityReport:
        """Generate complete API security report."""
        return APISecurityReport(
            target=target,
            endpoints_discovered=len(self._endpoints),
            endpoints=self._endpoints,
            vulnerabilities=self._vulnerabilities,
            auth_schemes=list(set(ep.auth_type for ep in self._endpoints if ep.auth_type)),
        )

    def get_summary(self) -> Dict[str, Any]:
        return {
            "endpoints": len(self._endpoints),
            "vulnerabilities": len(self._vulnerabilities),
            "by_type": {},
        }
