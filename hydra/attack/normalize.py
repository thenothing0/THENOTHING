"""
Response normalization (audit improvement #4 — pure, network-free).

Differential detection is only trustworthy if the two responses being compared are normalized the same
way. On real targets responses arrive gzip/deflate-compressed, in non-UTF-8 charsets, or as a SPA shell
that reflects nothing server-side. `ResponseNormalizer` makes the body comparable and flags noise:

  * `decode(raw, content_encoding, content_type)` — gunzip/inflate when needed, decode with the
    Content-Type charset (falling back to utf-8/replace) → stable text.
  * `is_spa_shell(text)` — recognises an empty single-page-app mount (`<div id=root/app>` + a JS
    bundle, no server-rendered content) so a payload "reflected" into a client-rendered template is
    not over-trusted as a server reflection.
  * `normalize(resp)` — decode + annotate a response dict in place (`normalized_body`, `charset`,
    `spa_shell`) so the detector/scan consume a clean signal.

Defensive (never raises), deterministic, no I/O.
"""

from __future__ import annotations

import gzip
import re
import zlib
from typing import Dict

_CHARSET_RE = re.compile(r"charset=([\w\-]+)", re.I)
# empty SPA mount point immediately followed (anywhere) by a JS bundle reference.
_SPA_MOUNT_RE = re.compile(r'<div[^>]*\bid=["\']?(root|app|__next|___gatsby)["\']?[^>]*>\s*</div>', re.I)
_BUNDLE_RE = re.compile(r'<script[^>]+src=["\'][^"\']+\.js', re.I)
_TAG_RE = re.compile(r"<[^>]+>")


class ResponseNormalizer:
    def decode(self, raw, content_encoding: str = "", content_type: str = "") -> str:
        if raw is None:
            return ""
        if isinstance(raw, str):
            return raw
        data = raw
        enc = (content_encoding or "").lower()
        try:
            if "gzip" in enc:
                data = gzip.decompress(data)
            elif "deflate" in enc:
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    data = zlib.decompress(data, -zlib.MAX_WBITS)   # raw deflate
            elif data[:2] == b"\x1f\x8b":                           # gzip magic w/o header hint
                data = gzip.decompress(data)
        except (OSError, zlib.error, EOFError):
            pass                                                    # leave as-is on bad stream
        m = _CHARSET_RE.search(content_type or "")
        charset = (m.group(1) if m else "utf-8")
        try:
            return data.decode(charset, "replace")
        except (LookupError, TypeError):
            return data.decode("utf-8", "replace")

    def is_spa_shell(self, text: str) -> bool:
        if not text or not _BUNDLE_RE.search(text):
            return False
        if not _SPA_MOUNT_RE.search(text):
            return False
        # almost no human-visible text outside tags → it's a client-rendered shell
        visible = _TAG_RE.sub("", text).strip()
        return len(visible) < 64

    def normalize(self, resp: Dict) -> Dict:
        """Annotate a response dict with a decoded `normalized_body`, `charset`, and `spa_shell`.
        Uses `raw` bytes when present, else the existing `body_snippet`."""
        ct = resp.get("content_type") or ""
        raw = resp.get("raw")
        text = (self.decode(raw, resp.get("content_encoding", ""), ct)
                if raw is not None else (resp.get("body_snippet") or ""))
        m = _CHARSET_RE.search(ct)
        resp["normalized_body"] = text
        resp["charset"] = (m.group(1).lower() if m else "utf-8")
        resp["spa_shell"] = self.is_spa_shell(text)
        return resp
