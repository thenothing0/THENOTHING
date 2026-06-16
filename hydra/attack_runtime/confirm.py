"""
Confirmation hooks (attack section improvement #3 — runtime/I/O side).

Closes the two confirmation loops that turn "suspected" into undeniable:

  * `BrowserConfirmer` — loads a URL in the real headless browser (`hydra/browser`, Playwright) and
    confirms XSS by ACTUAL JavaScript execution (a `dialog`/marker hook), capturing a screenshot for
    the report. Defensive: if Playwright isn't installed it returns an `unavailable` result rather
    than failing — the workflow then falls back to the differential verdict.
  * `OOBConfirmer` — correlates received out-of-band interactions (polled from the operator's OWN
    interactsh / Burp Collaborator instance via an injected `poller`) against issued OOB tokens →
    confirms blind SSRF / XXE / RCE. No live server is stood up here.

Both are injected into the workflow; both are gated upstream (only authorized targets ever reach
them). The poller is operator-supplied so nothing here talks to third-party infrastructure on its own.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional


class BrowserConfirmer:
    """Confirm DOM-executing XSS via the real headless browser + capture a screenshot."""

    def __init__(self, output_dir: str = "output/attack_screens", headless: bool = True):
        self.output_dir = output_dir
        self.headless = headless

    def confirm_xss(self, url: str, marker: str = "hydra-xss-confirmed") -> Dict:
        """Load `url` headless; report whether injected JS executed (dialog/marker) + a screenshot.

        Returns {confirmed: bool|None, screenshot: str, reason: str}. `confirmed=None` ⇒ the browser
        was unavailable (caller keeps the differential verdict)."""
        try:
            import asyncio
            return asyncio.run(self._run(url, marker))
        except Exception as e:                       # browser/runtime unavailable → inconclusive
            return {"confirmed": None, "screenshot": "", "reason": f"browser unavailable: {e}"}

    async def _run(self, url: str, marker: str) -> Dict:
        try:
            from playwright.async_api import async_playwright
        except Exception:
            return {"confirmed": None, "screenshot": "", "reason": "playwright not installed"}
        import os
        os.makedirs(self.output_dir, exist_ok=True)
        shot = os.path.join(self.output_dir, "xss.png")
        fired = {"v": False}
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self.headless)
            page = await browser.new_page()
            page.on("dialog", lambda d: (fired.__setitem__("v", True),
                                         __import__("asyncio").ensure_future(d.dismiss())))
            try:
                await page.goto(url, timeout=15000)
                await page.wait_for_timeout(800)
                await page.screenshot(path=shot)
            finally:
                await browser.close()
        return {"confirmed": bool(fired["v"]), "screenshot": shot if fired["v"] else "",
                "reason": "JS dialog executed in DOM" if fired["v"] else "no JS execution observed"}


class OOBConfirmer:
    """Correlate received OOB interactions (from the operator's own collaborator) to issued tokens."""

    def __init__(self, correlator, poller: Optional[Callable[[], List[Dict]]] = None):
        # correlator: hydra.attack.oob.OOBCorrelator ; poller(): -> list of interaction dicts
        self.correlator = correlator
        self.poller = poller

    def confirm(self) -> Dict:
        if self.poller is None:
            return {"confirmed_blind_findings": [], "count": 0,
                    "reason": "no OOB poller configured (point it at your collaborator)"}
        try:
            interactions = self.poller() or []
        except Exception as e:
            return {"confirmed_blind_findings": [], "count": 0, "reason": f"poll failed: {e}"}
        return self.correlator.correlate(interactions)
