"""
╔══════════════════════════════════════════════════════════════╗
║  GitHub Intelligence Module — Code Exposure Discovery       ║
║  Leaked secrets, API keys, internal domains, CI/CD exposure ║
║  Developer correlations, endpoint extraction                ║
╚══════════════════════════════════════════════════════════════╝

Correlation chain:
  employee → repository → secret → infrastructure → attack path
"""

import asyncio
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field

from hydra.osint import HTTPMixin, OSINTFinding, InfrastructureAsset

logger = logging.getLogger("hydra.osint.github")


# ──────────────────────────────────────────────
#  Secret Patterns
# ──────────────────────────────────────────────

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret_key": re.compile(r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]'),
    "github_token": re.compile(r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'),
    "slack_token": re.compile(r'xox[bporsca]-[0-9a-zA-Z]{10,48}'),
    "slack_webhook": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "google_oauth": re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
    "firebase_url": re.compile(r'https://[a-z0-9-]+\.firebaseio\.com'),
    "firebase_api_key": re.compile(r'(?i)firebase.*[\'"][A-Za-z0-9]{39}[\'"]'),
    "heroku_api_key": re.compile(r'(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    "mailgun_key": re.compile(r'key-[0-9a-zA-Z]{32}'),
    "twilio_key": re.compile(r'SK[0-9a-fA-F]{32}'),
    "sendgrid_key": re.compile(r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}'),
    "stripe_secret": re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    "stripe_publishable": re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),
    "square_token": re.compile(r'sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}'),
    "shopify_key": re.compile(r'shpat_[a-fA-F0-9]{32}'),
    "jwt_token": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "private_key": re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
    "generic_secret": re.compile(r'(?i)(password|passwd|pwd|secret|token|apikey|api_key|auth)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]'),
    "database_url": re.compile(r'(?i)(postgres|mysql|mongodb|redis)://[^\s\'\"]+'),
    "ip_address": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
    "internal_domain": re.compile(r'(?i)\b[\w-]+\.(internal|local|corp|intra|private|staging|dev)\.[a-z]{2,}\b'),
    "env_variable": re.compile(r'(?i)(DB_|AWS_|API_|SECRET_|PRIVATE_|AUTH_|TOKEN_|KEY_)[A-Z_]+=\S+'),
}

# Patterns for endpoint extraction from source code
ENDPOINT_PATTERNS = {
    "api_route": re.compile(r'[\'"]/(api|v[12]|rest)/[a-zA-Z0-9/_\-{}]+[\'"]'),
    "url_path": re.compile(r'[\'"]https?://[a-zA-Z0-9._\-]+/[a-zA-Z0-9/_\-{}?&=]+[\'"]'),
    "graphql_endpoint": re.compile(r'[\'"]/(graphql|gql)[\'"]'),
    "webhook_url": re.compile(r'[\'"]/(webhook|callback|hook|notify)[a-zA-Z0-9/_\-]*[\'"]'),
}


@dataclass
class GitHubSearchResult:
    """GitHub code search result."""
    repository: str
    file_path: str
    file_url: str
    snippet: str
    owner: str
    match_type: str
    secrets_found: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class DeveloperProfile:
    """Developer intelligence profile."""
    username: str
    name: str = ""
    email: str = ""
    company: str = ""
    repositories: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    exposed_secrets: int = 0
    related_domains: List[str] = field(default_factory=list)


class GitHubIntelligence(HTTPMixin):
    """
    GitHub intelligence module.

    Capabilities:
      - Discover leaked secrets & API keys
      - Extract internal domains & endpoints
      - Map CI/CD exposure
      - Correlate developers to infrastructure
      - Extract environment variable patterns
      - Discover infrastructure leakage

    Correlation chain:
      employee → repository → secret → infrastructure → attack path
    """

    GITHUB_API = "https://api.github.com"

    def __init__(self, token: str = ""):
        self.token = token
        self._headers = {"Accept": "application/vnd.github+json"}
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    async def search_code(self, query: str, max_pages: int = 3) -> List[Dict]:
        """Search GitHub code with the given query."""
        results = []
        for page in range(1, max_pages + 1):
            url = f"{self.GITHUB_API}/search/code?q={query}&page={page}&per_page=30"
            data = await self._http_get_json(url, headers=self._headers)
            if not data:
                break
            items = data.get("items", [])
            results.extend(items)
            if len(items) < 30:
                break
            # Rate limit courtesy
            await asyncio.sleep(2)
        return results

    async def search_target(self, target: str) -> List[OSINTFinding]:
        """
        Full GitHub intelligence search for a target domain.

        Searches for:
          - Domain mentions in code
          - API keys and secrets
          - Internal endpoints
          - Configuration files
          - Environment variables
        """
        findings = []
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        base_domain = ".".join(domain.split(".")[-2:])

        logger.info(f"🔍 GitHub intelligence search for {domain}")

        # Search queries — each targets a different exposure vector
        queries = [
            f'"{domain}" filename:.env',
            f'"{domain}" filename:config',
            f'"{base_domain}" password OR secret OR token OR api_key',
            f'"{domain}" filename:docker-compose.yml',
            f'"{domain}" filename:.yml path:.github',
            f'org:"{base_domain.split(".")[0]}" filename:.env',
        ]

        all_results = []
        for query in queries:
            try:
                results = await self.search_code(query, max_pages=2)
                all_results.extend(results)
            except Exception as e:
                logger.debug(f"GitHub search failed for query '{query}': {e}")
            await asyncio.sleep(1)  # Rate limit

        # Process results
        seen_repos: Set[str] = set()
        for item in all_results:
            repo = item.get("repository", {}).get("full_name", "")
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")

            if repo in seen_repos:
                continue
            seen_repos.add(repo)

            # Fetch file content for secret scanning
            content = await self._fetch_file_content(item)
            if not content:
                continue

            # Scan for secrets
            secrets = self._scan_for_secrets(content)
            if secrets:
                findings.append(OSINTFinding(
                    finding_type="leaked_secret",
                    title=f"Secrets found in {repo}/{file_path}",
                    description=(
                        f"Found {len(secrets)} potential secrets "
                        f"({', '.join(set(s['type'] for s in secrets))})"
                    ),
                    source="github", severity="high", confidence=0.7,
                    evidence={
                        "repository": repo,
                        "file": file_path,
                        "url": html_url,
                        "secrets": [
                            {"type": s["type"], "preview": s["preview"]}
                            for s in secrets
                        ],
                    },
                    related_assets=[domain],
                ))

            # Scan for endpoints
            endpoints = self._extract_endpoints(content, domain)
            if endpoints:
                findings.append(OSINTFinding(
                    finding_type="exposed_endpoint",
                    title=f"Endpoints found in {repo}",
                    description=f"Discovered {len(endpoints)} API/internal endpoints",
                    source="github", severity="info", confidence=0.6,
                    evidence={
                        "repository": repo,
                        "endpoints": endpoints[:30],
                    },
                    related_assets=[domain],
                ))

            # Scan for internal domains
            internal_domains = self._find_internal_domains(content, domain)
            if internal_domains:
                findings.append(OSINTFinding(
                    finding_type="internal_domain",
                    title=f"Internal domains found in {repo}",
                    description=f"Discovered {len(internal_domains)} internal/staging domains",
                    source="github", severity="medium", confidence=0.65,
                    evidence={
                        "repository": repo,
                        "domains": list(internal_domains),
                    },
                    related_assets=[domain],
                ))

        logger.info(
            f"🔍 GitHub OSINT: {len(findings)} findings from "
            f"{len(seen_repos)} repositories"
        )
        return findings

    async def _fetch_file_content(self, item: Dict) -> Optional[str]:
        """Fetch raw file content from GitHub."""
        download_url = item.get("download_url") or item.get("url")
        if not download_url:
            return None
        content = await self._http_get(download_url, headers=self._headers)
        if content and len(content) > 500_000:
            content = content[:500_000]  # Limit to 500KB
        return content

    def _scan_for_secrets(self, content: str) -> List[Dict[str, str]]:
        """Scan file content for leaked secrets."""
        found = []
        for secret_type, pattern in SECRET_PATTERNS.items():
            # Skip generic patterns that would match too much
            if secret_type in ("ip_address", "internal_domain", "env_variable"):
                continue
            matches = pattern.findall(content)
            for match in matches[:5]:  # Limit per type
                match_str = match if isinstance(match, str) else match[0]
                found.append({
                    "type": secret_type,
                    "preview": match_str[:20] + "..." if len(match_str) > 20 else match_str,
                    "length": len(match_str),
                })
        return found

    def _extract_endpoints(self, content: str, domain: str) -> List[str]:
        """Extract API endpoints from source code."""
        endpoints = set()
        for _name, pattern in ENDPOINT_PATTERNS.items():
            matches = pattern.findall(content)
            for match in matches:
                cleaned = match.strip("'\"")
                if domain in cleaned or cleaned.startswith("/"):
                    endpoints.add(cleaned)
        return sorted(endpoints)[:50]

    def _find_internal_domains(self, content: str, domain: str) -> Set[str]:
        """Find internal/staging/dev domains in code."""
        internal = set()
        base = ".".join(domain.split(".")[-2:])

        # Look for staging, dev, internal subdomains
        subdomain_pattern = re.compile(
            rf'[\w-]+\.(?:staging|dev|test|internal|local|corp|qa|uat)\.'
            rf'{re.escape(base)}',
            re.IGNORECASE,
        )
        for match in subdomain_pattern.findall(content):
            internal.add(match.lower())

        # Also check the generic internal domain pattern
        for match in SECRET_PATTERNS["internal_domain"].findall(content):
            if base.split(".")[0] in match.lower():
                internal.add(match.lower())

        return internal

    async def get_org_members(self, org: str) -> List[DeveloperProfile]:
        """Get public members of a GitHub organization."""
        url = f"{self.GITHUB_API}/orgs/{org}/members?per_page=100"
        data = await self._http_get_json(url, headers=self._headers)
        if not data:
            return []

        profiles = []
        for member in data[:50]:  # Limit
            username = member.get("login", "")
            user_data = await self._http_get_json(
                f"{self.GITHUB_API}/users/{username}",
                headers=self._headers,
            )
            if user_data:
                profiles.append(DeveloperProfile(
                    username=username,
                    name=user_data.get("name", ""),
                    email=user_data.get("email", ""),
                    company=user_data.get("company", ""),
                ))
            await asyncio.sleep(0.5)

        return profiles

    async def search_employee_repos(self, org: str, domain: str) -> List[OSINTFinding]:
        """Search employee personal repos for org-related secrets."""
        findings = []
        members = await self.get_org_members(org)

        for member in members[:20]:
            query = f'user:{member.username} "{domain}"'
            try:
                results = await self.search_code(query, max_pages=1)
                for item in results:
                    content = await self._fetch_file_content(item)
                    if content:
                        secrets = self._scan_for_secrets(content)
                        if secrets:
                            findings.append(OSINTFinding(
                                finding_type="employee_leak",
                                title=f"Employee {member.username} has org secrets in personal repo",
                                description=(
                                    f"Found {len(secrets)} secrets in "
                                    f"{item.get('repository', {}).get('full_name', '')}"
                                ),
                                source="github",
                                severity="high",
                                confidence=0.75,
                                evidence={
                                    "employee": member.username,
                                    "repository": item.get("repository", {}).get("full_name", ""),
                                    "secrets_types": [s["type"] for s in secrets],
                                },
                                related_assets=[domain],
                            ))
            except Exception as e:
                logger.debug(f"Employee repo search failed for {member.username}: {e}")
            await asyncio.sleep(1)

        return findings
