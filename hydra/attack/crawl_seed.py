"""
Crawl seeding (attack section — pure, network-free).

Feeds real discovered endpoints (e.g. from `katana_crawl` / `gau_urls`) into the scanner instead of a
single hand-picked URL. `CrawlSeeder.seeds()` de-duplicates a crawl's URL list down to one
representative per (host, path, parameter-set) SIGNATURE — so scanning covers the distinct injectable
endpoints without re-testing 500 URLs that differ only by parameter values. Deterministic; no I/O
(the crawling itself is done by the existing recon tools and the URLs are passed in).
"""

from __future__ import annotations

from typing import List
from urllib.parse import parse_qsl, urlparse


def param_signature(url: str) -> tuple:
    """(host, path, sorted-param-names) — the distinct-injectable-endpoint key."""
    p = urlparse(url if "://" in url else f"https://{url}")
    names = tuple(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)}))
    return (p.hostname or "", p.path or "/", names)


class CrawlSeeder:
    def seeds(self, urls: List[str], max_seeds: int = 50,
              params_only: bool = True, in_scope_hosts: List[str] = None) -> List[str]:
        """Distinct representative URLs to scan. params_only keeps only URLs with query parameters
        (the injectable ones); in_scope_hosts (optional) filters to those host suffixes."""
        seen = set()
        out: List[str] = []
        scope = [h.lower().lstrip("*.") for h in (in_scope_hosts or [])]
        for raw in urls:
            u = (raw or "").strip()
            if not u:
                continue
            sig = param_signature(u)
            host, _, names = sig
            if params_only and not names:
                continue
            if scope and not any(host == s or host.endswith("." + s) for s in scope):
                continue
            if sig in seen:
                continue
            seen.add(sig)
            out.append(u)
            if len(out) >= max(1, max_seeds):
                break
        return out

    def report(self, urls: List[str], max_seeds: int = 50) -> dict:
        s = self.seeds(urls, max_seeds=max_seeds)
        return {"input_urls": len(urls), "distinct_seeds": len(s), "seeds": s, "advisory": True}
