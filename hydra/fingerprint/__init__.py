"""
╔══════════════════════════════════════════════════════════════╗
║  Technology Fingerprinting Engine — Wappalyzer-style logic  ║
║  Infer frameworks, cloud providers, auth systems, CMS,     ║
║  JS frameworks, CDNs, server software from HTTP responses   ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.fingerprint")


@dataclass
class TechnologyMatch:
    """A detected technology."""
    name: str
    category: str  # framework, cms, cdn, server, language, analytics, etc.
    version: str = ""
    confidence: float = 0.5
    source: str = ""  # header, html, js, cookie, meta
    evidence: str = ""


@dataclass
class FingerprintResult:
    """Complete fingerprint result for a target."""
    target: str
    technologies: List[TechnologyMatch] = field(default_factory=list)
    server: str = ""
    powered_by: str = ""
    cloud_provider: str = ""
    waf_detected: str = ""
    framework: str = ""
    cms: str = ""
    js_framework: str = ""
    auth_system: str = ""
    cdn: str = ""
    fingerprint_time: float = 0.0
    raw_headers: Dict[str, str] = field(default_factory=dict)

    def get_technologies_by_category(self) -> Dict[str, List[TechnologyMatch]]:
        result: Dict[str, List[TechnologyMatch]] = {}
        for tech in self.technologies:
            result.setdefault(tech.category, []).append(tech)
        return result

    def get_intelligence_pack_triggers(self) -> List[str]:
        """Return which intelligence packs should be activated."""
        triggers = set()
        for tech in self.technologies:
            name_lower = tech.name.lower()
            if "wordpress" in name_lower: triggers.add("wordpress")
            if "laravel" in name_lower: triggers.add("laravel")
            if "next" in name_lower or "vercel" in name_lower: triggers.add("nextjs")
            if "graphql" in name_lower: triggers.add("graphql")
            if "aws" in name_lower or "amazon" in name_lower: triggers.add("aws")
            if "kubernetes" in name_lower or "k8s" in name_lower: triggers.add("kubernetes")
            if "oauth" in name_lower: triggers.add("oauth")
            if "cloudflare" in name_lower: triggers.add("cloudflare")
            if "firebase" in name_lower: triggers.add("firebase")
            if "supabase" in name_lower: triggers.add("supabase")
            if "django" in name_lower: triggers.add("django")
            if "express" in name_lower: triggers.add("express")
            if "spring" in name_lower: triggers.add("spring")
            if "react" in name_lower: triggers.add("react")
            if "angular" in name_lower: triggers.add("angular")
            if "vue" in name_lower: triggers.add("vue")
            if "asp.net" in name_lower or "aspnet" in name_lower: triggers.add("aspnet")
            if "nginx" in name_lower: triggers.add("nginx")
            if "apache" in name_lower: triggers.add("apache")
            if "jwt" in name_lower: triggers.add("jwt")
        return sorted(triggers)


# ──────────────────────────────────────────────
#  Fingerprint Signatures Database
# ──────────────────────────────────────────────

HEADER_SIGNATURES = {
    # Server software
    "nginx": {"header": "server", "pattern": re.compile(r'nginx/?(\S+)?', re.I), "category": "server"},
    "apache": {"header": "server", "pattern": re.compile(r'Apache/?(\S+)?', re.I), "category": "server"},
    "iis": {"header": "server", "pattern": re.compile(r'Microsoft-IIS/?(\S+)?', re.I), "category": "server"},
    "litespeed": {"header": "server", "pattern": re.compile(r'LiteSpeed', re.I), "category": "server"},
    "caddy": {"header": "server", "pattern": re.compile(r'Caddy', re.I), "category": "server"},
    "envoy": {"header": "server", "pattern": re.compile(r'envoy', re.I), "category": "server"},

    # Frameworks (X-Powered-By)
    "php": {"header": "x-powered-by", "pattern": re.compile(r'PHP/?(\S+)?', re.I), "category": "language"},
    "aspnet": {"header": "x-powered-by", "pattern": re.compile(r'ASP\.NET', re.I), "category": "framework"},
    "express": {"header": "x-powered-by", "pattern": re.compile(r'Express', re.I), "category": "framework"},
    "django": {"header": "x-powered-by", "pattern": re.compile(r'Django', re.I), "category": "framework"},

    # CDN / Cloud
    "cloudflare": {"header": "server", "pattern": re.compile(r'cloudflare', re.I), "category": "cdn"},
    "cloudflare_ray": {"header": "cf-ray", "pattern": re.compile(r'.+'), "category": "cdn", "name": "Cloudflare"},
    "cloudfront": {"header": "x-amz-cf-id", "pattern": re.compile(r'.+'), "category": "cdn", "name": "CloudFront (AWS)"},
    "akamai": {"header": "x-akamai-transformed", "pattern": re.compile(r'.+'), "category": "cdn", "name": "Akamai"},
    "fastly": {"header": "x-served-by", "pattern": re.compile(r'cache-', re.I), "category": "cdn", "name": "Fastly"},
    "vercel": {"header": "x-vercel-id", "pattern": re.compile(r'.+'), "category": "platform", "name": "Vercel"},
    "netlify": {"header": "x-nf-request-id", "pattern": re.compile(r'.+'), "category": "platform", "name": "Netlify"},
    "heroku": {"header": "via", "pattern": re.compile(r'vegur', re.I), "category": "platform", "name": "Heroku"},

    # WAF
    "aws_waf": {"header": "x-amzn-requestid", "pattern": re.compile(r'.+'), "category": "waf", "name": "AWS WAF"},
    "sucuri": {"header": "x-sucuri-id", "pattern": re.compile(r'.+'), "category": "waf", "name": "Sucuri WAF"},

    # Framework-specific
    "nextjs": {"header": "x-nextjs-cache", "pattern": re.compile(r'.+'), "category": "framework", "name": "Next.js"},
    "rails": {"header": "x-request-id", "pattern": re.compile(r'[a-f0-9-]{36}'), "category": "framework", "name": "Ruby on Rails"},

    # Auth
    "auth0": {"header": "x-auth0-requestid", "pattern": re.compile(r'.+'), "category": "auth", "name": "Auth0"},
}

HTML_SIGNATURES = [
    # CMS
    {"pattern": re.compile(r'wp-content|wp-includes|wordpress', re.I), "name": "WordPress", "category": "cms"},
    {"pattern": re.compile(r'Drupal\.settings|drupal\.js', re.I), "name": "Drupal", "category": "cms"},
    {"pattern": re.compile(r'joomla', re.I), "name": "Joomla", "category": "cms"},
    {"pattern": re.compile(r'shopify\.com/s/|cdn\.shopify', re.I), "name": "Shopify", "category": "ecommerce"},
    {"pattern": re.compile(r'squarespace\.com', re.I), "name": "Squarespace", "category": "cms"},
    {"pattern": re.compile(r'ghost\.org|ghost\.io', re.I), "name": "Ghost", "category": "cms"},

    # JS Frameworks
    {"pattern": re.compile(r'__NEXT_DATA__|_next/static|next\.js', re.I), "name": "Next.js", "category": "framework"},
    {"pattern": re.compile(r'__NUXT__|_nuxt/', re.I), "name": "Nuxt.js", "category": "framework"},
    {"pattern": re.compile(r'ng-version|angular\.(?:min\.)?js', re.I), "name": "Angular", "category": "js_framework"},
    {"pattern": re.compile(r'react(?:\.production|\.development|DOM)', re.I), "name": "React", "category": "js_framework"},
    {"pattern": re.compile(r'Vue\.js|vuejs|vue\.min\.js|vue\.runtime', re.I), "name": "Vue.js", "category": "js_framework"},
    {"pattern": re.compile(r'svelte|__svelte', re.I), "name": "Svelte", "category": "js_framework"},
    {"pattern": re.compile(r'ember\.js|ember-cli', re.I), "name": "Ember.js", "category": "js_framework"},

    # Analytics
    {"pattern": re.compile(r'google-analytics\.com|gtag/js|ga\.js', re.I), "name": "Google Analytics", "category": "analytics"},
    {"pattern": re.compile(r'hotjar\.com', re.I), "name": "Hotjar", "category": "analytics"},
    {"pattern": re.compile(r'segment\.com/analytics|analytics\.js', re.I), "name": "Segment", "category": "analytics"},
    {"pattern": re.compile(r'mixpanel\.com', re.I), "name": "Mixpanel", "category": "analytics"},

    # Auth / Identity
    {"pattern": re.compile(r'auth0\.com|auth0-js', re.I), "name": "Auth0", "category": "auth"},
    {"pattern": re.compile(r'cognito|aws-amplify', re.I), "name": "AWS Cognito", "category": "auth"},
    {"pattern": re.compile(r'firebase\.google\.com|firebase-auth', re.I), "name": "Firebase Auth", "category": "auth"},
    {"pattern": re.compile(r'supabase\.co|supabase-js', re.I), "name": "Supabase", "category": "platform"},
    {"pattern": re.compile(r'clerk\.com|clerk\.browser', re.I), "name": "Clerk", "category": "auth"},
    {"pattern": re.compile(r'keycloak', re.I), "name": "Keycloak", "category": "auth"},

    # Cloud / Infrastructure
    {"pattern": re.compile(r'amazonaws\.com', re.I), "name": "AWS", "category": "cloud"},
    {"pattern": re.compile(r'azure\.com|azure-cdn|azureedge', re.I), "name": "Azure", "category": "cloud"},
    {"pattern": re.compile(r'googleapis\.com|gstatic\.com', re.I), "name": "Google Cloud", "category": "cloud"},
    {"pattern": re.compile(r'digitalocean', re.I), "name": "DigitalOcean", "category": "cloud"},

    # GraphQL
    {"pattern": re.compile(r'graphql|__schema|IntrospectionQuery', re.I), "name": "GraphQL", "category": "api"},

    # Build tools / bundlers
    {"pattern": re.compile(r'webpack|webpackJsonp', re.I), "name": "Webpack", "category": "build"},
    {"pattern": re.compile(r'vite|/@vite/client', re.I), "name": "Vite", "category": "build"},
]

COOKIE_SIGNATURES = [
    {"pattern": re.compile(r'wordpress_|wp-settings'), "name": "WordPress", "category": "cms"},
    {"pattern": re.compile(r'PHPSESSID'), "name": "PHP", "category": "language"},
    {"pattern": re.compile(r'JSESSIONID'), "name": "Java", "category": "language"},
    {"pattern": re.compile(r'ASP\.NET'), "name": "ASP.NET", "category": "framework"},
    {"pattern": re.compile(r'connect\.sid'), "name": "Express.js", "category": "framework"},
    {"pattern": re.compile(r'_rails_session'), "name": "Ruby on Rails", "category": "framework"},
    {"pattern": re.compile(r'laravel_session'), "name": "Laravel", "category": "framework"},
    {"pattern": re.compile(r'django'), "name": "Django", "category": "framework"},
    {"pattern": re.compile(r'__cf_bm|cf_clearance'), "name": "Cloudflare", "category": "cdn"},
]

META_TAG_SIGNATURES = [
    {"name_attr": "generator", "patterns": [
        (re.compile(r'WordPress\s*([\d.]+)?', re.I), "WordPress", "cms"),
        (re.compile(r'Drupal\s*([\d.]+)?', re.I), "Drupal", "cms"),
        (re.compile(r'Joomla\s*([\d.]+)?', re.I), "Joomla", "cms"),
        (re.compile(r'Hugo\s*([\d.]+)?', re.I), "Hugo", "ssg"),
        (re.compile(r'Jekyll\s*([\d.]+)?', re.I), "Jekyll", "ssg"),
        (re.compile(r'Ghost\s*([\d.]+)?', re.I), "Ghost", "cms"),
    ]},
]


class TechnologyFingerprinter:
    """
    Technology fingerprinting engine.

    Uses Wappalyzer-style detection logic to identify:
      - Web servers (nginx, Apache, IIS)
      - Frameworks (Next.js, Laravel, Django, Express)
      - CMS platforms (WordPress, Drupal)
      - CDN/WAF (Cloudflare, Akamai, AWS WAF)
      - Cloud providers (AWS, Azure, GCP)
      - Auth systems (Auth0, Firebase Auth, Cognito)
      - JS frameworks (React, Angular, Vue)
      - Analytics platforms
      - API types (REST, GraphQL)
    """

    def __init__(self):
        self._cache: Dict[str, FingerprintResult] = {}

    async def fingerprint(self, target: str,
                          headers: Optional[Dict[str, str]] = None,
                          html: Optional[str] = None,
                          cookies: Optional[str] = None) -> FingerprintResult:
        """
        Fingerprint a target using available data.

        If headers/html are not provided, attempts to fetch them.
        """
        start = time.time()
        result = FingerprintResult(target=target)

        # Fetch data if not provided
        if headers is None or html is None:
            fetched = await self._fetch_target(target)
            if fetched:
                headers = headers or fetched.get("headers", {})
                html = html or fetched.get("html", "")
                cookies = cookies or fetched.get("cookies", "")

        headers = headers or {}
        html = html or ""
        cookies = cookies or ""

        result.raw_headers = headers

        # Apply all detection methods
        self._match_headers(headers, result)
        self._match_html(html, result)
        self._match_cookies(cookies, result)
        self._match_meta_tags(html, result)
        self._detect_cloud_provider(headers, html, result)
        self._detect_waf(headers, result)

        # Deduplicate
        result.technologies = self._deduplicate(result.technologies)

        # Set summary fields
        self._set_summary_fields(result)

        result.fingerprint_time = round(time.time() - start, 3)
        self._cache[target] = result

        logger.info(
            f"🔬 Fingerprinted {target}: "
            f"{len(result.technologies)} technologies detected "
            f"in {result.fingerprint_time}s"
        )
        return result

    async def _fetch_target(self, target: str) -> Optional[Dict]:
        """Fetch headers and HTML from target."""
        url = target if target.startswith("http") else f"https://{target}"
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=15),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    html = await resp.text()
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    cookies = "; ".join(
                        f"{c.key}={c.value}" for c in resp.cookies.values()
                    )
                    return {"headers": headers, "html": html, "cookies": cookies}
        except Exception as e:
            logger.debug(f"Failed to fetch {target}: {e}")
            return None

    def _match_headers(self, headers: Dict[str, str], result: FingerprintResult):
        """Match response headers against signature database."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for sig_name, sig in HEADER_SIGNATURES.items():
            header_key = sig["header"].lower()
            if header_key in headers_lower:
                match = sig["pattern"].search(headers_lower[header_key])
                if match:
                    name = sig.get("name", sig_name.title())
                    version = match.group(1) if match.lastindex else ""
                    result.technologies.append(TechnologyMatch(
                        name=name, category=sig["category"],
                        version=version or "", confidence=0.9,
                        source="header",
                        evidence=f"{sig['header']}: {headers_lower[header_key][:100]}",
                    ))

    def _match_html(self, html: str, result: FingerprintResult):
        """Match HTML content against signature database."""
        if not html:
            return
        # Only scan first 200KB for performance
        html_scan = html[:200_000]
        for sig in HTML_SIGNATURES:
            if sig["pattern"].search(html_scan):
                result.technologies.append(TechnologyMatch(
                    name=sig["name"], category=sig["category"],
                    confidence=0.7, source="html",
                    evidence=f"Pattern matched: {sig['pattern'].pattern[:60]}",
                ))

    def _match_cookies(self, cookies: str, result: FingerprintResult):
        """Match cookies against signature database."""
        if not cookies:
            return
        for sig in COOKIE_SIGNATURES:
            if sig["pattern"].search(cookies):
                result.technologies.append(TechnologyMatch(
                    name=sig["name"], category=sig["category"],
                    confidence=0.75, source="cookie",
                    evidence=f"Cookie pattern: {sig['pattern'].pattern}",
                ))

    def _match_meta_tags(self, html: str, result: FingerprintResult):
        """Match meta tag content."""
        if not html:
            return
        for meta_sig in META_TAG_SIGNATURES:
            name_attr = meta_sig["name_attr"]
            pattern = re.compile(
                rf'<meta\s+name=["\']?{name_attr}["\']?\s+content=["\']([^"\']+)["\']',
                re.I,
            )
            match = pattern.search(html[:50_000])
            if match:
                content = match.group(1)
                for tech_pattern, tech_name, tech_cat in meta_sig["patterns"]:
                    tech_match = tech_pattern.search(content)
                    if tech_match:
                        version = tech_match.group(1) if tech_match.lastindex else ""
                        result.technologies.append(TechnologyMatch(
                            name=tech_name, category=tech_cat,
                            version=version or "", confidence=0.95,
                            source="meta", evidence=f"generator: {content}",
                        ))

    def _detect_cloud_provider(self, headers: Dict, html: str,
                                result: FingerprintResult):
        """Detect cloud provider from multiple signals."""
        headers_str = json.dumps(headers).lower()
        combined = headers_str + (html[:10000] if html else "")

        cloud_signals = {
            "AWS": ["amazonaws.com", "x-amz-", "aws", "cloudfront"],
            "Google Cloud": ["googleapis.com", "gstatic.com", "appengine"],
            "Azure": ["azure", "azureedge", "windows.net"],
            "DigitalOcean": ["digitalocean"],
            "Vercel": ["vercel", "x-vercel"],
            "Netlify": ["netlify"],
            "Heroku": ["heroku", "vegur"],
            "Cloudflare": ["cloudflare", "cf-ray"],
        }

        for provider, signals in cloud_signals.items():
            score = sum(1 for s in signals if s in combined)
            if score >= 1:
                result.cloud_provider = provider
                break

    def _detect_waf(self, headers: Dict, result: FingerprintResult):
        """Detect Web Application Firewall."""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        waf_signals = {
            "Cloudflare": ["cf-ray", "cf-cache-status"],
            "AWS WAF": ["x-amzn-requestid"],
            "Sucuri": ["x-sucuri-id"],
            "Imperva": ["x-iinfo"],
            "Akamai": ["x-akamai-transformed"],
            "ModSecurity": ["mod_security", "modsecurity"],
        }

        for waf_name, headers_list in waf_signals.items():
            for h in headers_list:
                if h in headers_lower:
                    result.waf_detected = waf_name
                    return

    def _deduplicate(self, techs: List[TechnologyMatch]) -> List[TechnologyMatch]:
        """Remove duplicate detections, keeping highest confidence."""
        seen: Dict[str, TechnologyMatch] = {}
        for tech in techs:
            key = f"{tech.name}:{tech.category}"
            if key not in seen or tech.confidence > seen[key].confidence:
                seen[key] = tech
        return sorted(seen.values(), key=lambda t: t.confidence, reverse=True)

    def _set_summary_fields(self, result: FingerprintResult):
        """Set summary fields from detected technologies."""
        for tech in result.technologies:
            cat = tech.category.lower()
            if cat == "server" and not result.server:
                result.server = f"{tech.name} {tech.version}".strip()
            elif cat == "framework" and not result.framework:
                result.framework = tech.name
            elif cat == "cms" and not result.cms:
                result.cms = tech.name
            elif cat in ("js_framework",) and not result.js_framework:
                result.js_framework = tech.name
            elif cat in ("cdn",) and not result.cdn:
                result.cdn = tech.name
            elif cat in ("auth",) and not result.auth_system:
                result.auth_system = tech.name

    def get_cached(self, target: str) -> Optional[FingerprintResult]:
        return self._cache.get(target)
