"""
Out-of-band pollers (attack section — runtime/I/O side).

A real poller for the OOB confirmation loop: it fetches received interactions from the OPERATOR'S OWN
collaborator and hands them to `hydra.attack.oob.OOBCorrelator` (via `OOBConfirmer`). Two flavours:

  * `OOBPoller(poll_url)` — generic: GETs a JSON endpoint returning interactions
    (`{"interactions":[{"host","protocol","remote_addr"}]}` or a bare list);
  * `InteractshPoller(server, correlation_id, token)` — builds the poll URL for an interactsh-style
    `/poll?id=&secret=` endpoint (operator-hosted or oast; full RSA-decrypt correlation can be plugged
    in by passing a custom `parse`).

It polls the OOB infrastructure, NOT the target — so it is not the bug-bounty gate's concern; it only
ever talks to the endpoint the operator supplies. Defensive: any error → empty list.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional


class OOBPoller:
    def __init__(self, poll_url: str, timeout: float = 10.0, verify_tls: bool = True,
                 parse: Optional[Callable[[object], List[Dict]]] = None):
        self.poll_url = poll_url
        self.timeout = timeout
        self._ctx = None if verify_tls else ssl._create_unverified_context()
        self._parse = parse or self._default_parse

    @staticmethod
    def _default_parse(data) -> List[Dict]:
        rows = data.get("interactions", data) if isinstance(data, dict) else data
        out: List[Dict] = []
        for it in (rows or []):
            if isinstance(it, dict):
                host = it.get("host") or it.get("full-id") or it.get("unique-id") or ""
                out.append({"host": str(host),
                            "protocol": str(it.get("protocol", it.get("proto", ""))),
                            "remote_addr": str(it.get("remote_addr", it.get("remote-address", "")))})
        return out

    def poll(self) -> List[Dict]:
        if not self.poll_url:
            return []
        try:
            req = urllib.request.Request(self.poll_url, headers={"User-Agent": "hydra-oob/1.0"})
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self._ctx))
            with opener.open(req, timeout=self.timeout) as r:
                raw = r.read(1 << 20)
            return self._parse(json.loads(raw.decode("utf-8", "replace")))
        except (urllib.error.URLError, ValueError, OSError):
            return []


class InteractshPoller(OOBPoller):
    def __init__(self, server: str, correlation_id: str, token: str = "",
                 scheme: str = "https", **kw):
        url = f"{scheme}://{server.strip('/')}/poll?id={correlation_id}"
        if token:
            url += f"&secret={token}"
        super().__init__(url, **kw)
