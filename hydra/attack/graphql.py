"""
GraphQL testing (attack section improvement #3 — pure request/response logic).

Generates the high-value GraphQL checks (introspection, field-suggestion leakage when introspection is
"disabled", GET-based introspection, batching) as request specs, and analyzes the responses. Detection
+ PoC only — it reads the schema/errors, it never mutates data or amplifies load (batching is capped
at a small probe count). Execution goes through the gated executor.
"""

from __future__ import annotations

import json
from typing import Dict, List, Tuple
from urllib.parse import quote

_INTROSPECTION = ("query{__schema{queryType{name} types{name kind "
                  "fields{name args{name}}}}}")


def _post(url: str, query: str) -> Dict:
    return {"method": "POST", "url": url, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"query": query})}


class GraphQLTester:
    def requests(self, url: str) -> List[Dict]:
        return [
            {"name": "introspection", "request": _post(url, _INTROSPECTION)},
            {"name": "field_suggestion",
             "request": _post(url, "query{__schema{nonExistentFieldXyz}}")},
            {"name": "get_introspection",
             "request": {"method": "GET", "url": f"{url}?query={quote(_INTROSPECTION)}",
                         "headers": {}}},
            {"name": "batching",
             "request": {"method": "POST", "url": url,
                         "headers": {"Content-Type": "application/json"},
                         "body": json.dumps([{"query": "{__typename}"} for _ in range(5)])}},
        ]

    def analyze(self, name: str, resp: Dict) -> Tuple[str, str]:
        body = (resp.get("body_snippet") or "").lower()
        if not resp.get("executed"):
            return "suspected", "no response"
        if name in ("introspection", "get_introspection") and ("__schema" in body or '"types"' in body
                                                               or "querytype" in body):
            return "confirmed", "introspection enabled — full schema disclosed"
        if name == "field_suggestion" and "did you mean" in body:
            return "confirmed", "field-suggestion leak (schema recoverable despite introspection off)"
        if name == "batching" and body.count("__typename") >= 2:
            return "confirmed", "query batching enabled (brute-force / rate-limit bypass surface)"
        return "suspected", "no clear GraphQL signal"

    def report(self) -> Dict:
        return {"checks": ["introspection", "field_suggestion", "get_introspection", "batching"],
                "note": "detection/PoC only — schema/errors read, no data mutated", "advisory": True}
