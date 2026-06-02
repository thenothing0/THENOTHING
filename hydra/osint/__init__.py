"""
╔══════════════════════════════════════════════════════════════╗
║  OSINT Intelligence Layer — Passive Reconnaissance Engine   ║
║  Infrastructure attribution, organization mapping, cloud    ║
║  exposure discovery, public leak analysis, attack surface   ║
║  enrichment. No active scanning — pure OSINT collection.    ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import time
import re
import socket
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger("hydra.osint")


# ──────────────────────────────────────────────
#  Data Models
# ──────────────────────────────────────────────

@dataclass
class InfrastructureAsset:
    """Discovered infrastructure asset."""
    asset: str
    asset_type: str  # domain, ip, cidr, cloud_resource, api_endpoint
    source: str
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)


@dataclass
class OSINTFinding:
    """OSINT intelligence finding."""
    finding_type: str  # leaked_secret, exposed_endpoint, shadow_infra, employee_intel
    title: str
    description: str
    source: str
    severity: str = "info"
    confidence: float = 0.5
    evidence: Dict[str, Any] = field(default_factory=dict)
    related_assets: List[str] = field(default_factory=list)
    discovered_at: float = field(default_factory=time.time)


@dataclass
class OSINTReport:
    """Complete OSINT intelligence report."""
    target: str
    assets: List[InfrastructureAsset] = field(default_factory=list)
    findings: List[OSINTFinding] = field(default_factory=list)
    infrastructure_map: Dict[str, Any] = field(default_factory=dict)
    organization_profile: Dict[str, Any] = field(default_factory=dict)
    attack_surface: Dict[str, Any] = field(default_factory=dict)
    cloud_exposure: List[Dict[str, Any]] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)


# ──────────────────────────────────────────────
#  HTTP Client Mixin
# ──────────────────────────────────────────────

class HTTPMixin:
    """Shared HTTP client for OSINT modules."""

    async def _http_get(self, url: str, headers: Dict = None,
                        timeout: int = 30) -> Optional[str]:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=headers or {},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        return await resp.text()
        except Exception as e:
            logger.debug(f"HTTP GET failed ({url}): {e}")
        return None

    async def _http_get_json(self, url: str, headers: Dict = None,
                             timeout: int = 30) -> Optional[Any]:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=headers or {},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception as e:
            logger.debug(f"HTTP JSON failed ({url}): {e}")
        return None


# ──────────────────────────────────────────────
#  Certificate Transparency (crt.sh)
# ──────────────────────────────────────────────

class CertTransparencyIntel(HTTPMixin):
    """Query certificate transparency logs via crt.sh."""

    CRT_SH_URL = "https://crt.sh/?q={}&output=json"

    async def search(self, domain: str) -> List[InfrastructureAsset]:
        """Find all certificates issued for a domain."""
        url = self.CRT_SH_URL.format(f"%.{domain}")
        data = await self._http_get_json(url)
        if not data:
            return []

        assets = []
        seen: Set[str] = set()
        for entry in data:
            name = entry.get("name_value", "")
            for subdomain in name.split("\n"):
                subdomain = subdomain.strip().lower()
                if subdomain and subdomain not in seen and domain in subdomain:
                    seen.add(subdomain)
                    assets.append(InfrastructureAsset(
                        asset=subdomain, asset_type="domain", source="crt.sh",
                        confidence=0.9,
                        metadata={
                            "issuer": entry.get("issuer_name", ""),
                            "not_before": entry.get("not_before", ""),
                            "not_after": entry.get("not_after", ""),
                        },
                    ))

        logger.info(f"🔍 crt.sh: found {len(assets)} unique subdomains for {domain}")
        return assets


# ──────────────────────────────────────────────
#  Shodan Intelligence
# ──────────────────────────────────────────────

class ShodanIntel(HTTPMixin):
    """Shodan passive intelligence integration."""

    SHODAN_API = "https://api.shodan.io"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    async def host_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get host information from Shodan."""
        if not self.api_key:
            return None
        url = f"{self.SHODAN_API}/shodan/host/{ip}?key={self.api_key}"
        return await self._http_get_json(url)

    async def search(self, query: str, max_results: int = 100) -> List[Dict]:
        """Search Shodan for matching hosts."""
        if not self.api_key:
            return []
        url = f"{self.SHODAN_API}/shodan/host/search?key={self.api_key}&query={query}"
        data = await self._http_get_json(url)
        if not data:
            return []
        return data.get("matches", [])[:max_results]

    async def dns_resolve(self, domain: str) -> Optional[Dict]:
        """Resolve domain to IP via Shodan DNS."""
        if not self.api_key:
            return None
        url = f"{self.SHODAN_API}/dns/resolve?hostnames={domain}&key={self.api_key}"
        return await self._http_get_json(url)

    async def reverse_dns(self, ip: str) -> Optional[Dict]:
        """Reverse DNS lookup via Shodan."""
        if not self.api_key:
            return None
        url = f"{self.SHODAN_API}/dns/reverse?ips={ip}&key={self.api_key}"
        return await self._http_get_json(url)

    async def gather_intelligence(self, target: str) -> List[OSINTFinding]:
        """Gather comprehensive Shodan intelligence for a target."""
        findings = []
        if not self.api_key:
            return findings

        # Resolve domain to IP
        dns_data = await self.dns_resolve(target)
        if dns_data and target in dns_data:
            ip = dns_data[target]
            host_data = await self.host_info(ip)
            if host_data:
                # Open ports
                ports = host_data.get("ports", [])
                if ports:
                    findings.append(OSINTFinding(
                        finding_type="exposed_service",
                        title=f"Open ports on {target}",
                        description=f"Shodan detected {len(ports)} open ports: {ports[:20]}",
                        source="shodan", severity="info", confidence=0.9,
                        evidence={"ports": ports, "ip": ip},
                        related_assets=[target],
                    ))

                # Vulnerabilities
                vulns = host_data.get("vulns", [])
                if vulns:
                    findings.append(OSINTFinding(
                        finding_type="known_vulnerability",
                        title=f"Known CVEs on {target}",
                        description=f"Shodan reports {len(vulns)} known vulnerabilities",
                        source="shodan", severity="high", confidence=0.8,
                        evidence={"cves": vulns[:50], "ip": ip},
                        related_assets=[target],
                    ))

                # SSL/TLS
                ssl_data = host_data.get("ssl", {})
                if ssl_data:
                    cert = ssl_data.get("cert", {})
                    findings.append(OSINTFinding(
                        finding_type="ssl_certificate",
                        title=f"SSL certificate details for {target}",
                        description=f"Issuer: {cert.get('issuer', {}).get('O', 'unknown')}",
                        source="shodan", severity="info", confidence=0.95,
                        evidence={"ssl": ssl_data},
                    ))

        return findings


# ──────────────────────────────────────────────
#  Censys Intelligence
# ──────────────────────────────────────────────

class CensysIntel(HTTPMixin):
    """Censys passive intelligence."""

    CENSYS_API = "https://search.censys.io/api/v2"

    def __init__(self, api_id: str = "", api_secret: str = ""):
        self.api_id = api_id
        self.api_secret = api_secret

    async def search_hosts(self, query: str) -> List[Dict]:
        """Search Censys for hosts matching a query."""
        if not self.api_id or not self.api_secret:
            return []
        import base64
        auth = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}
        url = f"{self.CENSYS_API}/hosts/search?q={query}&per_page=25"
        data = await self._http_get_json(url, headers=headers)
        if not data:
            return []
        return data.get("result", {}).get("hits", [])


# ──────────────────────────────────────────────
#  SecurityTrails Intelligence
# ──────────────────────────────────────────────

class SecurityTrailsIntel(HTTPMixin):
    """SecurityTrails DNS and domain intelligence."""

    ST_API = "https://api.securitytrails.com/v1"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    async def get_subdomains(self, domain: str) -> List[str]:
        """Get subdomains from SecurityTrails."""
        if not self.api_key:
            return []
        url = f"{self.ST_API}/domain/{domain}/subdomains"
        headers = {"APIKEY": self.api_key}
        data = await self._http_get_json(url, headers=headers)
        if not data:
            return []
        subs = data.get("subdomains", [])
        return [f"{s}.{domain}" for s in subs]

    async def get_dns_history(self, domain: str, record_type: str = "a") -> List[Dict]:
        """Get DNS history for a domain."""
        if not self.api_key:
            return []
        url = f"{self.ST_API}/history/{domain}/dns/{record_type}"
        headers = {"APIKEY": self.api_key}
        data = await self._http_get_json(url, headers=headers)
        if not data:
            return []
        return data.get("records", [])

    async def get_whois(self, domain: str) -> Optional[Dict]:
        """Get WHOIS data from SecurityTrails."""
        if not self.api_key:
            return None
        url = f"{self.ST_API}/domain/{domain}/whois"
        headers = {"APIKEY": self.api_key}
        return await self._http_get_json(url, headers=headers)


# ──────────────────────────────────────────────
#  DNS Intelligence (WHOIS + ASN)
# ──────────────────────────────────────────────

class DNSIntel(HTTPMixin):
    """DNS and WHOIS intelligence gathering."""

    async def resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses."""
        try:
            ips = []
            result = socket.getaddrinfo(domain, None)
            for item in result:
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)
            return ips
        except Exception:
            return []

    async def get_asn_info(self, ip: str) -> Optional[Dict]:
        """Get ASN information for an IP using Team Cymru."""
        url = f"https://api.hackertarget.com/aslookup/?q={ip}"
        data = await self._http_get(url)
        if data and "API count exceeded" not in data:
            parts = data.strip().split(",")
            if len(parts) >= 3:
                return {
                    "ip": parts[0].strip() if parts else ip,
                    "asn": parts[1].strip() if len(parts) > 1 else "",
                    "description": parts[2].strip() if len(parts) > 2 else "",
                }
        return None

    async def reverse_dns(self, ip: str) -> List[str]:
        """Reverse DNS lookup."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return [hostname]
        except Exception:
            return []

    async def gather_dns_intelligence(self, domain: str) -> Dict[str, Any]:
        """Comprehensive DNS intelligence for a domain."""
        ips = await self.resolve_domain(domain)
        asn_info = []
        reverse_dns_results = {}

        for ip in ips[:5]:
            asn = await self.get_asn_info(ip)
            if asn:
                asn_info.append(asn)
            rdns = await self.reverse_dns(ip)
            if rdns:
                reverse_dns_results[ip] = rdns

        return {
            "domain": domain,
            "ips": ips,
            "asn_info": asn_info,
            "reverse_dns": reverse_dns_results,
        }


# ──────────────────────────────────────────────
#  Wayback Machine Intelligence
# ──────────────────────────────────────────────

class WaybackIntel(HTTPMixin):
    """Wayback Machine historical URL intelligence."""

    CDX_API = "https://web.archive.org/cdx/search/cdx"

    async def search(self, domain: str, limit: int = 1000) -> List[str]:
        """Find historical URLs from Wayback Machine."""
        url = (
            f"{self.CDX_API}?url=*.{domain}/*"
            f"&output=json&fl=original&limit={limit}&collapse=urlkey"
        )
        data = await self._http_get_json(url, timeout=60)
        if not data or len(data) < 2:
            return []
        # First row is header
        urls = [row[0] for row in data[1:] if row]
        logger.info(f"🕰️ Wayback: found {len(urls)} historical URLs for {domain}")
        return urls

    async def find_interesting_endpoints(self, domain: str) -> List[OSINTFinding]:
        """Find interesting endpoints from historical data."""
        urls = await self.search(domain, limit=2000)
        findings = []

        # Interesting patterns
        patterns = {
            "api_endpoint": re.compile(r'/api/|/v[12]/|/graphql|/rest/', re.I),
            "admin_panel": re.compile(r'/admin|/dashboard|/panel|/manage', re.I),
            "config_file": re.compile(r'\.env|\.config|\.yml|\.yaml|\.json$|\.xml$', re.I),
            "backup_file": re.compile(r'\.bak|\.backup|\.old|\.copy|\.orig', re.I),
            "sensitive_path": re.compile(r'/internal|/debug|/test|/staging|/dev/', re.I),
            "auth_endpoint": re.compile(r'/login|/auth|/oauth|/signup|/register', re.I),
        }

        categorized: Dict[str, List[str]] = {k: [] for k in patterns}
        for url in urls:
            for category, pattern in patterns.items():
                if pattern.search(url) and len(categorized[category]) < 50:
                    categorized[category].append(url)

        for category, matched_urls in categorized.items():
            if matched_urls:
                findings.append(OSINTFinding(
                    finding_type=f"wayback_{category}",
                    title=f"Historical {category.replace('_', ' ')} endpoints",
                    description=f"Found {len(matched_urls)} historical {category} URLs via Wayback Machine",
                    source="wayback_machine", severity="info", confidence=0.6,
                    evidence={"urls": matched_urls[:20], "total": len(matched_urls)},
                    related_assets=[domain],
                ))

        return findings


# ──────────────────────────────────────────────
#  OSINT Intelligence Engine (Orchestrator)
# ──────────────────────────────────────────────

class OSINTIntelligenceEngine(HTTPMixin):
    """
    Central OSINT orchestrator.

    Coordinates all OSINT modules to build a complete
    intelligence picture of a target's attack surface.

    Capabilities:
      - Passive reconnaissance
      - Infrastructure attribution
      - Organization mapping
      - Cloud exposure discovery
      - Public leak analysis
      - Attack surface enrichment
    """

    def __init__(self, api_keys: Optional[Dict[str, str]] = None):
        keys = api_keys or {}
        self.crtsh = CertTransparencyIntel()
        self.shodan = ShodanIntel(api_key=keys.get("shodan", ""))
        self.censys = CensysIntel(
            api_id=keys.get("censys_id", ""),
            api_secret=keys.get("censys_secret", ""),
        )
        self.sectrails = SecurityTrailsIntel(api_key=keys.get("securitytrails", ""))
        self.dns = DNSIntel()
        self.wayback = WaybackIntel()

        # GitHub intel loaded separately
        self._github_intel = None
        self._report: Optional[OSINTReport] = None

    def set_github_intel(self, github_intel):
        """Attach GitHub intelligence module."""
        self._github_intel = github_intel

    async def run_full_osint(self, target: str) -> OSINTReport:
        """
        Execute full OSINT intelligence gathering.

        Orchestrates all modules concurrently for maximum speed.
        """
        report = OSINTReport(target=target)
        start = time.time()
        logger.info(f"🔍 Starting OSINT intelligence gathering for {target}")

        # Phase 1: DNS + Certificate Transparency (no API keys needed)
        phase1_tasks = [
            self.crtsh.search(target),
            self.dns.gather_dns_intelligence(target),
            self.wayback.find_interesting_endpoints(target),
        ]
        phase1_results = await asyncio.gather(*phase1_tasks, return_exceptions=True)

        # Process crt.sh results
        if isinstance(phase1_results[0], list):
            report.assets.extend(phase1_results[0])
            report.infrastructure_map["subdomains_crtsh"] = len(phase1_results[0])

        # Process DNS results
        if isinstance(phase1_results[1], dict):
            report.infrastructure_map["dns"] = phase1_results[1]
            # Add IPs as assets
            for ip in phase1_results[1].get("ips", []):
                report.assets.append(InfrastructureAsset(
                    asset=ip, asset_type="ip", source="dns_resolution",
                    confidence=0.95,
                ))

        # Process Wayback results
        if isinstance(phase1_results[2], list):
            report.findings.extend(phase1_results[2])

        # Phase 2: API-based intelligence (concurrent)
        phase2_tasks = []
        if self.shodan.api_key:
            phase2_tasks.append(self.shodan.gather_intelligence(target))
        if self.sectrails.api_key:
            phase2_tasks.append(self.sectrails.get_subdomains(target))

        if phase2_tasks:
            phase2_results = await asyncio.gather(*phase2_tasks, return_exceptions=True)
            for result in phase2_results:
                if isinstance(result, list):
                    if result and isinstance(result[0], OSINTFinding):
                        report.findings.extend(result)
                    elif result and isinstance(result[0], str):
                        for sub in result:
                            report.assets.append(InfrastructureAsset(
                                asset=sub, asset_type="domain",
                                source="securitytrails", confidence=0.85,
                            ))

        # Phase 3: GitHub intelligence
        if self._github_intel:
            try:
                github_results = await self._github_intel.search_target(target)
                report.findings.extend(github_results)
            except Exception as e:
                logger.warning(f"GitHub OSINT failed: {e}")

        # Build attack surface summary
        report.attack_surface = self._build_attack_surface(report)
        report.completed_at = time.time()
        report.duration = round(time.time() - start, 2)
        self._report = report

        logger.info(
            f"🔍 OSINT complete for {target}: "
            f"{len(report.assets)} assets, {len(report.findings)} findings "
            f"in {report.duration}s"
        )
        return report

    def _build_attack_surface(self, report: OSINTReport) -> Dict[str, Any]:
        """Build attack surface summary from all gathered intelligence."""
        domains = set()
        ips = set()
        services = []
        cloud_resources = []

        for asset in report.assets:
            if asset.asset_type == "domain":
                domains.add(asset.asset)
            elif asset.asset_type == "ip":
                ips.add(asset.asset)
            elif asset.asset_type == "cloud_resource":
                cloud_resources.append(asset.asset)

        # Classify findings
        leaked_secrets = [f for f in report.findings if f.finding_type == "leaked_secret"]
        exposed_services = [f for f in report.findings if f.finding_type == "exposed_service"]
        shadow_infra = [f for f in report.findings if f.finding_type == "shadow_infra"]

        return {
            "total_assets": len(report.assets),
            "unique_domains": len(domains),
            "unique_ips": len(ips),
            "cloud_resources": len(cloud_resources),
            "leaked_secrets": len(leaked_secrets),
            "exposed_services": len(exposed_services),
            "shadow_infrastructure": len(shadow_infra),
            "findings_by_severity": self._count_by_severity(report.findings),
            "top_domains": sorted(domains)[:50],
            "ip_addresses": sorted(ips)[:20],
        }

    @staticmethod
    def _count_by_severity(findings: List[OSINTFinding]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def get_report(self) -> Optional[OSINTReport]:
        return self._report
