"""
Burp / browser capture bridge — receive selected traffic from the companion
Burp extension (or any HTTP client) into THENOTHING, and query it from the agent.

Mirrors PentesterFlow's `--burp` ingest server, hardened against the exact
defects called out in PentesterFlow's own AUDIT.md:
  * **M9 (unbounded capture → OOM):** every store is LRU-bounded — total
    requests, distinct endpoints, and per-endpoint param sets all have hard caps.
  * **M11 (terminal-escape injection from ingested data):** all ingested text is
    run through a control-byte scrubber before it can reach a transcript/log.
  * Bind 127.0.0.1 ONLY, gate writes behind a per-session random bearer token,
    and cap request bodies — a captured target must not be able to reach the
    operator's box or DoS the bridge.

The store is the unit-testable core; ``start_bridge`` is a thin aiohttp wrapper.
"""

from __future__ import annotations

import re
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Strip C0/C1 control bytes except tab/newline/CR (M11): ESC, CSI, OSC, etc. so
# attacker-controlled captured URLs/headers can't drive the operator's terminal.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

DEFAULT_MAX_REQUESTS = 5000
DEFAULT_MAX_ENDPOINTS = 2000
DEFAULT_MAX_PARAMS_PER_ENDPOINT = 256
MAX_BODY_BYTES = 4 * 1024 * 1024  # 4 MiB ingest cap


def scrub(text: str) -> str:
    """Remove terminal control bytes from ingested text (M11)."""
    if not text:
        return ""
    return _CONTROL_RE.sub("", str(text))


@dataclass
class CapturedRequest:
    method: str
    url: str
    host: str = ""
    status: int = 0
    raw: str = ""               # full raw request material for replay/evidence
    note: str = ""
    ts: float = 0.0
    params: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"method": self.method, "url": self.url, "host": self.host,
                "status": self.status, "note": self.note, "ts": self.ts,
                "params": self.params, "raw_len": len(self.raw)}


class CaptureStore:
    """Bounded capture store. Newest wins; oldest evicted (LRU by insertion)."""

    def __init__(self, max_requests: int = DEFAULT_MAX_REQUESTS,
                 max_endpoints: int = DEFAULT_MAX_ENDPOINTS,
                 max_params: int = DEFAULT_MAX_PARAMS_PER_ENDPOINT):
        self._requests: "OrderedDict[str, CapturedRequest]" = OrderedDict()
        self._endpoints: "OrderedDict[str, set]" = OrderedDict()
        self._issues: "OrderedDict[str, Dict]" = OrderedDict()   # scanner issues
        self._timeline: List[Dict] = []                          # session recording
        self._max_requests = max_requests
        self._max_endpoints = max_endpoints
        self._max_params = max_params

    def add(self, method: str, url: str, *, host: str = "", status: int = 0,
            raw: str = "", note: str = "", params: Optional[List[str]] = None) -> CapturedRequest:
        url = scrub(url)
        raw = scrub(raw[:MAX_BODY_BYTES])
        cr = CapturedRequest(method=scrub(method).upper()[:12] or "GET", url=url,
                             host=scrub(host), status=int(status or 0), raw=raw,
                             note=scrub(note), ts=time.time(),
                             params=[scrub(p) for p in (params or [])][: self._max_params])
        key = f"{cr.method} {cr.url}"
        self._requests[key] = cr
        self._requests.move_to_end(key)
        while len(self._requests) > self._max_requests:
            self._requests.popitem(last=False)  # evict oldest
        # endpoint-level param accumulation (bounded both ways)
        ep = f"{cr.method} {cr.url.split('?', 1)[0]}"
        pset = self._endpoints.setdefault(ep, set())
        self._endpoints.move_to_end(ep)
        for p in cr.params:
            if len(pset) < self._max_params:
                pset.add(p)
        while len(self._endpoints) > self._max_endpoints:
            self._endpoints.popitem(last=False)
        # Append to the bounded session-recording timeline.
        self._record("request", f"{cr.method} {cr.url}")
        return cr

    def add_bulk(self, items: List[Dict]) -> Dict:
        """Site-map import: ingest many request records at once (bounded per-item)."""
        n = 0
        for it in items[:self._max_requests]:
            if not isinstance(it, dict) or not it.get("url"):
                continue
            self.add(it.get("method", "GET"), it["url"], host=it.get("host", ""),
                     status=it.get("status", 0), raw=it.get("raw", ""),
                     note=it.get("note", ""), params=it.get("params") or [])
            n += 1
        return {"imported": n, "stats": self.stats()}

    def add_issue(self, name: str, url: str, severity: str = "info", *, detail: str = "",
                  request: str = "", response: str = "", confidence: str = "") -> Dict:
        """Record a scanner issue (Burp Scanner). Bounded + scrubbed. Becomes a
        DRAFT finding via the burp_issue MCP tool's findings round-trip."""
        iid = f"I-{secrets.token_hex(6)}"
        issue = {"id": iid, "name": scrub(name)[:200], "url": scrub(url),
                 "severity": (severity or "info").lower(), "confidence": scrub(confidence)[:40],
                 "detail": scrub(detail)[:8000],
                 "request": scrub(request[:MAX_BODY_BYTES]),
                 "response": scrub(response[:MAX_BODY_BYTES]), "ts": time.time()}
        self._issues[iid] = issue
        self._issues.move_to_end(iid)
        while len(self._issues) > self._max_requests:
            self._issues.popitem(last=False)
        self._record("issue", f"{issue['severity']}: {issue['name']}")
        return issue

    def issues(self, limit: int = 50) -> List[Dict]:
        items = list(self._issues.values())[-limit:]
        # Return metadata (omit big request/response blobs; fetch raw via get_issue).
        return [{k: v for k, v in i.items() if k not in ("request", "response")}
                for i in reversed(items)]

    def get_issue(self, issue_id: str) -> Optional[Dict]:
        return self._issues.get(issue_id)

    def get_raw(self, method: str, url: str) -> Optional[str]:
        """Repeater: the stored raw request material for replay/evidence."""
        cr = self._requests.get(f"{scrub(method).upper()} {scrub(url)}")
        return cr.raw if cr else None

    def _record(self, kind: str, summary: str) -> None:
        self._timeline.append({"kind": kind, "summary": summary[:200], "ts": time.time()})
        # Bound the recording so a long capture can't grow without limit.
        if len(self._timeline) > self._max_requests:
            self._timeline = self._timeline[-self._max_requests:]

    def timeline(self, limit: int = 100) -> List[Dict]:
        return self._timeline[-limit:]

    def requests(self, limit: int = 50) -> List[Dict]:
        items = list(self._requests.values())[-limit:]
        return [r.to_dict() for r in reversed(items)]

    def endpoints(self, limit: int = 100) -> List[Dict]:
        out = []
        for ep, pset in list(self._endpoints.items())[-limit:]:
            out.append({"endpoint": ep, "params": sorted(pset)})
        return list(reversed(out))

    def stats(self) -> Dict:
        return {"requests": len(self._requests), "endpoints": len(self._endpoints),
                "issues": len(self._issues), "timeline": len(self._timeline),
                "caps": {"max_requests": self._max_requests,
                         "max_endpoints": self._max_endpoints,
                         "max_params_per_endpoint": self._max_params}}

    def clear(self) -> None:
        self._requests.clear()
        self._endpoints.clear()
        self._issues.clear()
        self._timeline.clear()


# A process-wide store the MCP tools read and the bridge writes.
STORE = CaptureStore()


def new_token() -> str:
    """Per-session bearer token gating ingest writes."""
    return secrets.token_hex(16)


async def start_bridge(port: int = 9999, token: str = "", store: Optional[CaptureStore] = None):
    """Start the localhost ingest server (aiohttp). Bound to 127.0.0.1 only.

    Returns (runner, url, token). POST /ingest (Bearer token) accepts a JSON
    request record; GET /health is open. Import is lazy so the module loads even
    where aiohttp is absent.
    """
    from aiohttp import web  # lazy import

    st = store or STORE
    tok = token or new_token()

    async def health(_req):
        return web.json_response({"ok": True, **st.stats()})

    async def ingest(req: "web.Request"):
        if req.headers.get("Authorization", "") != f"Bearer {tok}":
            return web.json_response({"error": "unauthorized"}, status=401)
        if req.content_length and req.content_length > MAX_BODY_BYTES:
            return web.json_response({"error": "body too large"}, status=413)
        try:
            body = await req.json()
        except Exception:
            return web.json_response({"error": "invalid json"}, status=400)
        cr = st.add(method=body.get("method", "GET"), url=body.get("url", ""),
                    host=body.get("host", ""), status=body.get("status", 0),
                    raw=body.get("raw", ""), note=body.get("note", ""),
                    params=body.get("params") or [])
        return web.json_response({"ok": True, "stored": cr.to_dict()})

    app = web.Application(client_max_size=MAX_BODY_BYTES + 1024)
    app.add_routes([web.get("/health", health), web.post("/ingest", ingest)])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)  # localhost ONLY
    await site.start()
    return runner, f"http://127.0.0.1:{port}", tok
