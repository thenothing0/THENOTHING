"""
Finding-level dedup & correlation (improvement #3 — one bug, one report).

The same root-cause bug often surfaces many times: stored XSS reflected at three pages, SQLi reachable
through two params on the same endpoint. Submitted separately that's noise (and duplicate-report risk).
`FindingCorrelator` merges findings that share a root cause — `(vuln_class, normalized endpoint)`, where
the endpoint path is normalized so `/user/12` and `/user/99` collapse — into ONE finding carrying every
instance (point/url). The strongest verdict and best evidence are kept on the merged finding.

Pure, deterministic, advisory; reorders/merges only — invents nothing.
"""

from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

_VERDICT_RANK = {"confirmed": 2, "single_signal": 1, "suspected": 1, "unconfirmed": 0, "": 0}
_NUM_SEG = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-", re.I)


def normalize_endpoint(url: str) -> str:
    """Collapse id-like path segments so the same endpoint with different ids shares a signature."""
    if not url:
        return ""
    p = urlparse(url if "://" in url else f"https://{url}")
    segs = []
    for s in p.path.split("/"):
        if _NUM_SEG.match(s) or _UUID.match(s):
            segs.append("{id}")
        else:
            segs.append(s)
    return f"{p.netloc}{'/'.join(segs)}" or p.path


class FindingCorrelator:
    def signature(self, finding: Dict) -> str:
        vc = (finding.get("vuln_class") or "").lower()
        ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else finding
        url = (ev.get("request") or {}).get("url") or finding.get("target") or ""
        return f"{vc}|{normalize_endpoint(url)}"

    def merge(self, findings: List[Dict]) -> Dict:
        groups: Dict[str, List[Dict]] = {}
        order: List[str] = []
        for f in findings:
            sig = self.signature(f)
            if sig not in groups:
                groups[sig] = []
                order.append(sig)
            groups[sig].append(f)

        merged: List[Dict] = []
        for sig in order:
            members = groups[sig]
            best = max(members, key=lambda m: _VERDICT_RANK.get(m.get("verdict", ""), 0))
            instances = sorted({m.get("point", "") or
                                ((m.get("evidence") or {}).get("request") or {}).get("url", "")
                                for m in members})
            row = dict(best)
            row["signature"] = sig
            row["instances"] = instances
            row["instance_count"] = len(members)
            merged.append(row)

        return {"original_count": len(findings), "merged_count": len(merged),
                "duplicates_collapsed": len(findings) - len(merged),
                "merged_findings": merged, "advisory": True}
