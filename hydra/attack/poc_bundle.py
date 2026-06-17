"""
Replayable PoC bundles + finding re-verification (improvement #1 — accepted-bounty multiplier).

A triager accepts a finding when they can re-run it in seconds and watch it fire. This turns a confirmed
finding into a self-contained, replayable artifact and lets the operator re-prove it on demand:

  * `build_bundle(finding)` (pure) — assembles the exact request(s), the request/response pair, the
    copy-paste `curl`, the differential indicators that prove it, and the screenshot path into one
    bundle, and renders a Markdown PoC + an executable `.sh`. `write_bundle(...)` persists it under
    `output/poc/` (disposable artifacts, never canonical knowledge).
  * `FindingReverifier` (gated, uses the executor) — replays a stored finding's request against a fresh
    baseline and re-runs the differential + two-signal logic → `reproduces: true|false` with fresh
    evidence. This is what survives the gap between "I found it" and "the triager opened the ticket".

Gated (deny-by-default on replay), PoC-only (replays the SAME benign PoC request, escalates nothing).
Deterministic given the executor.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional

from hydra.attack.detection import DifferentialDetector
from hydra.attack.evidence import curl_repro
from hydra.attack.two_signal import Signal, TwoSignalConfirmer


def _finding_evidence(finding: Dict) -> Dict:
    """A finding may carry its evidence inline or under `evidence` — normalize."""
    ev = finding.get("evidence")
    return ev if isinstance(ev, dict) else finding


def build_bundle(finding: Dict) -> Dict:
    """Assemble a self-contained, replayable PoC bundle from a (confirmed) finding."""
    ev = _finding_evidence(finding)
    req = ev.get("request") or {}
    resp = ev.get("response") or {}
    curl = ev.get("curl") or curl_repro(req.get("method", "GET"), req.get("url", ""),
                                        req.get("headers"), req.get("body", ""))
    indicators = ev.get("indicators") or []
    confirmation = ev.get("confirmation") or {}
    vc = finding.get("vuln_class") or ev.get("vuln_class") or "finding"
    bid = hashlib.sha1(f"{vc}|{req.get('url','')}|{req.get('payload','')}".encode()).hexdigest()[:12]
    md = "\n".join([
        f"## PoC — {vc.upper()} ({finding.get('verdict', ev.get('verdict', 'confirmed'))})",
        "", "**Reproduction:**", "```bash", curl, "```",
        f"**Observed response:** {resp.get('status')} ({resp.get('length', '?')} bytes)",
        "**Proof indicators:** " + (", ".join(indicators) if indicators else "(see confirmation)"),
        (f"**Independent signals:** {', '.join(confirmation.get('families', []))}"
         if confirmation else ""),
        (f"**Screenshot:** {ev.get('screenshot_path')}" if ev.get("screenshot_path") else ""),
    ])
    return {"bundle_id": bid, "vuln_class": vc,
            "verdict": finding.get("verdict", ev.get("verdict", "confirmed")),
            "replay_request": req, "response": resp, "curl": curl, "indicators": indicators,
            "confirmation": confirmation, "screenshot_path": ev.get("screenshot_path", ""),
            "markdown": md, "shell": f"#!/bin/sh\n{curl}\n", "advisory": True}


def write_bundle(finding: Dict, out_dir: Optional[Path] = None) -> Dict:
    """Persist a bundle (json + .sh + .md) under output/poc/<bundle_id>/. Best-effort, never raises."""
    bundle = build_bundle(finding)
    try:
        base = Path(out_dir) if out_dir else Path(__file__).resolve().parents[2] / "output" / "poc"
        d = base / bundle["bundle_id"]
        d.mkdir(parents=True, exist_ok=True)
        (d / "poc.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        (d / "repro.sh").write_text(bundle["shell"], encoding="utf-8")
        (d / "poc.md").write_text(bundle["markdown"], encoding="utf-8")
        bundle["written_to"] = str(d)
    except OSError as e:
        bundle["written_to"] = ""
        bundle["write_error"] = str(e)
    return bundle


class FindingReverifier:
    def __init__(self, gate=None, executor=None, detector: Optional[DifferentialDetector] = None,
                 two_signal: Optional[TwoSignalConfirmer] = None):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate
        if executor is None:
            from hydra.attack_runtime import HttpExecutor
            executor = HttpExecutor(gate=gate)
        self.executor = executor
        self.detector = detector or DifferentialDetector()
        self.two_signal = two_signal or TwoSignalConfirmer()

    def reverify(self, finding: Dict, baseline_marker: str = "hydrabaseline0") -> Dict:
        """Replay the finding's stored request and re-judge it (deny-by-default)."""
        ev = _finding_evidence(finding)
        req = dict(ev.get("request") or {})
        url = req.get("url", "")
        vc = (finding.get("vuln_class") or ev.get("vuln_class") or "").lower()
        if not url:
            return {"error": "finding has no stored request to replay", "advisory": True}
        decision = self.gate.authorize(url, "exploitation")
        if not decision.authorized:
            return {"authorized": False, "reason": decision.reason, "advisory": True}

        # fresh baseline at the same endpoint (strip the payload param value to a benign marker)
        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
        p = urlparse(url)
        q = parse_qsl(p.query, keep_blank_values=True)
        base_q = urlencode([(k, baseline_marker) for k, _ in q]) if q else ""
        base_req = {"method": req.get("method", "GET"),
                    "url": urlunparse(p._replace(query=base_q)),
                    "headers": req.get("headers", {})}
        base_resp = self.executor(base_req)
        resp = self.executor(req)
        signals: List[Signal] = self.detector.signals(vc, base_resp, req.get("payload", ""), resp)
        conf = self.two_signal.assess(signals)
        reproduces = conf.verdict == "confirmed"
        return {"vuln_class": vc, "target": url, "authorized": True, "poc_only": True,
                "reproduces": reproduces, "verdict": conf.verdict,
                "confirmation": conf.to_dict(),
                "fresh_status": resp.get("status"), "baseline_status": base_resp.get("status"),
                "note": ("finding STILL reproduces against a fresh baseline" if reproduces
                         else "finding did NOT reproduce — re-triage before submitting"),
                "advisory": True}
