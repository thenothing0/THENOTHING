"""
Injection-point discovery (attack section improvement #4 — pure, network-free).

Replaces "inject into a fixed ?q=" with enumeration of the REAL injectable locations of a request:
query parameters, form/body fields, JSON keys (recursively), a safe subset of headers, cookies, and
path segments. Each `InjectionPoint.apply(value)` returns a new request dict with the payload placed at
exactly that location — so the workflow can test every point × payload. Deterministic; no I/O.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Callable, Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Headers that are meaningful & safe to fuzz for injection (no auth/host spoofing here).
_FUZZABLE_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
                     "Origin", "True-Client-IP"]


@dataclass
class InjectionPoint:
    location: str          # query | body | json | header | cookie | path
    name: str
    apply: Callable[[str], Dict]

    def describe(self) -> Dict:
        return {"location": self.location, "name": self.name}


def _with_query(req: Dict, key: str, value: str) -> Dict:
    r = copy.deepcopy(req)
    p = urlparse(r["url"])
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[key] = value
    r["url"] = urlunparse(p._replace(query=urlencode(q)))
    return r


def _with_path_segment(req: Dict, idx: int, value: str) -> Dict:
    r = copy.deepcopy(req)
    p = urlparse(r["url"])
    segs = p.path.split("/")
    segs[idx] = value
    r["url"] = urlunparse(p._replace(path="/".join(segs)))
    return r


def _with_header(req: Dict, name: str, value: str) -> Dict:
    r = copy.deepcopy(req)
    r.setdefault("headers", {})[name] = value
    return r


def _with_cookie(req: Dict, name: str, value: str) -> Dict:
    r = copy.deepcopy(req)
    cookies = dict(c.split("=", 1) for c in r.get("headers", {}).get("Cookie", "").split("; ")
                   if "=" in c)
    cookies[name] = value
    r.setdefault("headers", {})["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return r


def _with_form(req: Dict, key: str, value: str) -> Dict:
    r = copy.deepcopy(req)
    body = dict(parse_qsl(r.get("body") or "", keep_blank_values=True))
    body[key] = value
    r["body"] = urlencode(body)
    return r


def _with_json(req: Dict, path: List, value: str) -> Dict:
    r = copy.deepcopy(req)
    obj = json.loads(r.get("body") or "{}")
    cur = obj
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value
    r["body"] = json.dumps(obj)
    return r


class InjectionPointFinder:
    def __init__(self, include_headers: bool = True, include_path: bool = True):
        self.include_headers = include_headers
        self.include_path = include_path

    def find(self, request: Dict) -> List[InjectionPoint]:
        req = dict(request)
        req.setdefault("method", "GET")
        req.setdefault("headers", {})
        points: List[InjectionPoint] = []
        p = urlparse(req["url"])

        # query parameters
        for key, _ in parse_qsl(p.query, keep_blank_values=True):
            points.append(InjectionPoint("query", key,
                                         lambda v, k=key: _with_query(req, k, v)))

        # body — form-encoded or JSON
        ctype = (req["headers"].get("Content-Type") or "").lower()
        body = req.get("body") or ""
        if body and ("json" in ctype or body.lstrip().startswith(("{", "["))):
            try:
                self._json_points(json.loads(body), [], req, points)
            except (ValueError, TypeError):
                pass
        elif body:
            for key, _ in parse_qsl(body, keep_blank_values=True):
                points.append(InjectionPoint("body", key,
                                             lambda v, k=key: _with_form(req, k, v)))

        # cookies
        for c in req["headers"].get("Cookie", "").split("; "):
            if "=" in c:
                name = c.split("=", 1)[0]
                points.append(InjectionPoint("cookie", name,
                                             lambda v, n=name: _with_cookie(req, n, v)))

        # headers (safe subset)
        if self.include_headers:
            for h in _FUZZABLE_HEADERS:
                points.append(InjectionPoint("header", h, lambda v, n=h: _with_header(req, n, v)))

        # path segments (non-empty)
        if self.include_path:
            for i, seg in enumerate(p.path.split("/")):
                if seg:
                    points.append(InjectionPoint("path", f"segment[{i}]",
                                                 lambda v, idx=i: _with_path_segment(req, idx, v)))

        # de-dup by (location, name) preserving order
        seen, uniq = set(), []
        for pt in points:
            key = (pt.location, pt.name)
            if key not in seen:
                seen.add(key)
                uniq.append(pt)
        return uniq

    def _json_points(self, obj, path, req, points) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    self._json_points(v, path + [k], req, points)
                else:
                    full = path + [k]
                    points.append(InjectionPoint("json", ".".join(map(str, full)),
                                                 lambda val, pp=full: _with_json(req, pp, val)))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self._json_points(v, path + [i], req, points)
