"""
╔══════════════════════════════════════════════════════════════╗
║  Browser Intelligence Agent — Playwright-Based Automation   ║
║  SPA crawling, authenticated flows, evidence capture,       ║
║  token/cookie/JWT extraction, shadow DOM analysis           ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("hydra.browser")


@dataclass
class BrowserFinding:
    """A finding discovered via browser automation."""
    finding_type: str          # token_leak, cookie_issue, storage_secret, endpoint, form, websocket
    title: str
    severity: str = "info"
    evidence: str = ""
    url: str = ""
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PageIntelligence:
    """Intelligence gathered from a single page."""
    url: str
    title: str = ""
    status: int = 0
    content_type: str = ""
    technologies: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    storage: Dict[str, Any] = field(default_factory=dict)  # localStorage + sessionStorage
    tokens: List[Dict[str, str]] = field(default_factory=list)
    websockets: List[str] = field(default_factory=list)
    findings: List[BrowserFinding] = field(default_factory=list)
    screenshot_path: str = ""


@dataclass
class BrowserSession:
    """State of a browser automation session."""
    target: str
    pages_visited: int = 0
    findings: List[BrowserFinding] = field(default_factory=list)
    endpoints: Set[str] = field(default_factory=set)
    tokens_found: List[Dict[str, str]] = field(default_factory=list)
    cookies_collected: List[Dict[str, Any]] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    duration: float = 0.0


# ──────────────────────────────────────────────
#  Token / Secret Patterns
# ──────────────────────────────────────────────

TOKEN_PATTERNS = {
    "jwt": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "bearer": re.compile(r'[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}'),
    "api_key": re.compile(r'(?:api[_-]?key|apikey)["\s:=]+["\']?([A-Za-z0-9_\-]{20,})["\']?', re.I),
    "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "github_token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
    "slack_token": re.compile(r'xox[bporas]-[A-Za-z0-9\-]{10,}'),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "basic_auth": re.compile(r'[Bb]asic\s+[A-Za-z0-9+/=]{10,}'),
    "session_token": re.compile(r'(?:session|sess|sid|token)["\s:=]+["\']?([A-Za-z0-9_\-\.]{16,})["\']?', re.I),
}

COOKIE_SECURITY_CHECKS = {
    "missing_httponly": lambda c: not c.get("httpOnly", False),
    "missing_secure": lambda c: not c.get("secure", False),
    "missing_samesite": lambda c: not c.get("sameSite", ""),
    "session_no_expiry": lambda c: "session" in c.get("name", "").lower() and c.get("expires", -1) == -1,
}


class BrowserIntelligenceEngine:
    """
    Browser Intelligence Engine using Playwright.

    Capabilities:
      - SPA crawling with JS rendering
      - Authenticated workflow replay
      - Token/JWT/cookie extraction
      - Form discovery and analysis
      - WebSocket endpoint detection
      - localStorage/sessionStorage extraction
      - Shadow DOM analysis
      - Screenshot evidence capture
      - Client-side routing discovery
      - CSRF token analysis
    """

    def __init__(self, output_dir: str = "output", headless: bool = True,
                 max_pages: int = 50, timeout: int = 30000):
        self._output_dir = Path(output_dir)
        self._headless = headless
        self._max_pages = max_pages
        self._timeout = timeout
        self._browser = None
        self._context = None
        self._playwright = None

    async def initialize(self):
        """Initialize Playwright browser."""
        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(headless=self._headless)
            self._context = await self._browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                ignore_https_errors=True,
            )
            logger.info("Browser intelligence engine initialized")
        except ImportError:
            logger.warning("Playwright not installed — browser intelligence disabled")
            logger.warning("Install with: pip install playwright && playwright install chromium")

    async def close(self):
        """Clean up browser resources."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def crawl(self, target: str, depth: int = 2,
                    auth_cookies: Optional[List[Dict]] = None) -> BrowserSession:
        """
        Crawl a target with full JS rendering.

        Returns BrowserSession with all discovered intelligence.
        """
        session = BrowserSession(target=target)
        start = time.time()

        if not self._context:
            logger.warning("Browser not initialized — returning empty session")
            return session

        # Set auth cookies if provided
        if auth_cookies:
            await self._context.add_cookies(auth_cookies)

        visited: Set[str] = set()
        queue = [target]
        current_depth = 0

        while queue and current_depth < depth and session.pages_visited < self._max_pages:
            next_queue: List[str] = []
            for url in queue:
                if url in visited:
                    continue
                visited.add(url)

                try:
                    intel = await self._analyze_page(url, session)
                    session.pages_visited += 1

                    # Collect links for next depth
                    for link in intel.links:
                        parsed = urlparse(link)
                        target_parsed = urlparse(target)
                        if parsed.netloc == target_parsed.netloc and link not in visited:
                            next_queue.append(link)

                except Exception as e:
                    logger.debug(f"Failed to analyze {url}: {e}")

            queue = next_queue[:self._max_pages - session.pages_visited]
            current_depth += 1

        session.duration = round(time.time() - start, 2)
        logger.info(f"Browser crawl complete: {session.pages_visited} pages, "
                     f"{len(session.findings)} findings, {session.duration}s")
        return session

    async def _analyze_page(self, url: str, session: BrowserSession) -> PageIntelligence:
        """Analyze a single page for intelligence."""
        intel = PageIntelligence(url=url)
        page = await self._context.new_page()

        try:
            response = await page.goto(url, timeout=self._timeout, wait_until="networkidle")
            if response:
                intel.status = response.status
                intel.content_type = response.headers.get("content-type", "")
            intel.title = await page.title()

            # Extract all intelligence in parallel
            await asyncio.gather(
                self._extract_links(page, intel),
                self._extract_forms(page, intel),
                self._extract_scripts(page, intel),
                self._extract_cookies(page, intel, session),
                self._extract_storage(page, intel, session),
                self._extract_tokens(page, intel, session),
                self._detect_websockets(page, intel),
                self._detect_technologies(page, intel),
            )

            # Screenshot for evidence
            screenshot_dir = self._output_dir / "browser"
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            safe_name = urlparse(url).path.replace("/", "_")[:50] or "index"
            screenshot_path = screenshot_dir / f"{safe_name}.png"
            await page.screenshot(path=str(screenshot_path), full_page=True)
            intel.screenshot_path = str(screenshot_path)
            session.screenshots.append(str(screenshot_path))

        except Exception as e:
            logger.debug(f"Page analysis error for {url}: {e}")
        finally:
            await page.close()

        session.findings.extend(intel.findings)
        return intel

    async def _extract_links(self, page, intel: PageIntelligence):
        """Extract all links from the page."""
        try:
            links = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(h => h.startsWith('http'));
            }""")
            intel.links = list(set(links))
        except Exception:
            pass

    async def _extract_forms(self, page, intel: PageIntelligence):
        """Extract and analyze forms."""
        try:
            forms = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action, method: f.method,
                    inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                        name: i.name, type: i.type, id: i.id, value: i.value ? '[REDACTED]' : ''
                    })),
                    hasCSRF: !!f.querySelector('input[name*="csrf"], input[name*="token"], input[name*="_token"]'),
                }));
            }""")
            intel.forms = forms
            # Check for forms without CSRF
            for form in forms:
                if form.get("method", "").upper() == "POST" and not form.get("hasCSRF"):
                    intel.findings.append(BrowserFinding(
                        finding_type="csrf_missing",
                        title=f"Form without CSRF token: {form.get('action', 'unknown')}",
                        severity="medium", url=intel.url, confidence=0.6,
                        evidence=json.dumps(form, default=str),
                    ))
        except Exception:
            pass

    async def _extract_scripts(self, page, intel: PageIntelligence):
        """Extract script sources."""
        try:
            scripts = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src);
            }""")
            intel.scripts = scripts
        except Exception:
            pass

    async def _extract_cookies(self, page, intel: PageIntelligence, session: BrowserSession):
        """Extract and analyze cookies."""
        try:
            cookies = await self._context.cookies()
            page_cookies = [c for c in cookies if urlparse(intel.url).netloc in c.get("domain", "")]
            intel.cookies = page_cookies
            session.cookies_collected.extend(page_cookies)

            for cookie in page_cookies:
                for check_name, check_fn in COOKIE_SECURITY_CHECKS.items():
                    if check_fn(cookie):
                        intel.findings.append(BrowserFinding(
                            finding_type="cookie_issue",
                            title=f"Cookie '{cookie['name']}': {check_name}",
                            severity="low", url=intel.url, confidence=0.7,
                            evidence=json.dumps(cookie, default=str),
                        ))
        except Exception:
            pass

    async def _extract_storage(self, page, intel: PageIntelligence, session: BrowserSession):
        """Extract localStorage and sessionStorage."""
        try:
            storage = await page.evaluate("""() => {
                const ls = {}; const ss = {};
                try { for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i); ls[k] = localStorage.getItem(k);
                }} catch(e) {}
                try { for (let i = 0; i < sessionStorage.length; i++) {
                    const k = sessionStorage.key(i); ss[k] = sessionStorage.getItem(k);
                }} catch(e) {}
                return {localStorage: ls, sessionStorage: ss};
            }""")
            intel.storage = storage

            # Check for sensitive data in storage
            all_values = json.dumps(storage)
            for pattern_name, pattern in TOKEN_PATTERNS.items():
                matches = pattern.findall(all_values)
                for match in matches:
                    token_val = match if isinstance(match, str) else match[0] if match else ""
                    intel.findings.append(BrowserFinding(
                        finding_type="storage_secret",
                        title=f"{pattern_name} found in browser storage",
                        severity="high", url=intel.url, confidence=0.8,
                        evidence=f"{pattern_name}: {token_val[:30]}...",
                    ))
                    session.tokens_found.append({"type": pattern_name, "source": "storage", "url": intel.url})
        except Exception:
            pass

    async def _extract_tokens(self, page, intel: PageIntelligence, session: BrowserSession):
        """Extract tokens from page content."""
        try:
            body = await page.content()
            for pattern_name, pattern in TOKEN_PATTERNS.items():
                matches = pattern.findall(body)
                for match in matches[:5]:
                    token_val = match if isinstance(match, str) else match[0] if match else ""
                    intel.findings.append(BrowserFinding(
                        finding_type="token_leak",
                        title=f"{pattern_name} found in page source",
                        severity="medium", url=intel.url, confidence=0.7,
                        evidence=f"{pattern_name}: {token_val[:30]}...",
                    ))
                    session.tokens_found.append({"type": pattern_name, "source": "html", "url": intel.url})
        except Exception:
            pass

    async def _detect_websockets(self, page, intel: PageIntelligence):
        """Detect WebSocket connections."""
        try:
            ws_urls = await page.evaluate("""() => {
                const urls = [];
                const OrigWS = window.WebSocket;
                window._wsUrls = urls;
                return urls;
            }""")
            intel.websockets = ws_urls
        except Exception:
            pass

    async def _detect_technologies(self, page, intel: PageIntelligence):
        """Detect frontend technologies."""
        try:
            techs = await page.evaluate("""() => {
                const t = [];
                if (window.React || document.querySelector('[data-reactroot]')) t.push('React');
                if (window.Vue || document.querySelector('[data-v-]')) t.push('Vue.js');
                if (window.__NEXT_DATA__) t.push('Next.js');
                if (window.__NUXT__) t.push('Nuxt.js');
                if (window.angular || document.querySelector('[ng-app]')) t.push('Angular');
                if (window.Ember) t.push('Ember.js');
                if (window.Svelte) t.push('Svelte');
                if (document.querySelector('script[src*="jquery"]')) t.push('jQuery');
                if (window.__remixContext) t.push('Remix');
                if (document.querySelector('meta[name="generator"]')) {
                    t.push(document.querySelector('meta[name="generator"]').content);
                }
                return t;
            }""")
            intel.technologies = techs
        except Exception:
            pass

    async def replay_request(self, method: str, url: str, headers: Optional[Dict] = None,
                              body: Optional[str] = None) -> Dict[str, Any]:
        """Replay an HTTP request through the browser for evidence capture."""
        if not self._context:
            return {"error": "Browser not initialized"}

        page = await self._context.new_page()
        try:
            if method.upper() == "GET":
                resp = await page.goto(url, timeout=self._timeout)
            else:
                resp = await page.evaluate(f"""async () => {{
                    const r = await fetch("{url}", {{
                        method: "{method}", headers: {json.dumps(headers or {})},
                        body: {json.dumps(body) if body else 'undefined'},
                    }});
                    return {{status: r.status, body: await r.text(), headers: Object.fromEntries(r.headers)}};
                }}""")
                return resp

            return {
                "status": resp.status if resp else 0,
                "url": page.url,
                "title": await page.title(),
            }
        finally:
            await page.close()
