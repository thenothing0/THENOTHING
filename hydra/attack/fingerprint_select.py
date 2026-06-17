"""
Technology-fingerprint-driven payload & class selection (improvement #5 — quality per scan).

A generic scan wastes payloads on a stack that can't be vulnerable to them. Given a fingerprint (the
techs from `whatweb_detect` / `wafw00f` / headers), this advises WHICH vuln classes are worth testing
and reorders payloads so the stack-relevant ones go first (a Postgres target gets `pg_sleep`, a Jinja2
target gets `{{7*7}}`, a Node/Express target gets prototype-pollution + NoSQL, a PHP target gets the
`php://filter` LFI). Targeted beats generic — fewer requests, fewer false positives, faster confirms.

Pure, deterministic, advisory; it only RANKS and recommends — the gated scanner still does the sending.
"""

from __future__ import annotations

from typing import Dict, List

# tech token → vuln classes that tech makes worth testing (with a short reason).
_TECH_CLASSES: Dict[str, List[str]] = {
    "wordpress": ["xss", "sqli", "lfi", "open_redirect"],
    "drupal": ["sqli", "xss"], "joomla": ["sqli", "xss"],
    "php": ["lfi", "sqli", "cmdi"], "laravel": ["sqli", "ssti"],
    "mysql": ["sqli"], "mariadb": ["sqli"], "postgres": ["sqli"], "postgresql": ["sqli"],
    "mssql": ["sqli"], "oracle": ["sqli"], "sqlite": ["sqli"],
    "mongodb": ["nosqli"], "mongo": ["nosqli"], "couchdb": ["nosqli"],
    "express": ["nosqli", "prototype_pollution"], "node.js": ["prototype_pollution", "nosqli"],
    "nodejs": ["prototype_pollution", "nosqli"],
    "java": ["ssti", "xxe"], "spring": ["ssti", "xxe"], "tomcat": ["xxe", "lfi"],
    "freemarker": ["ssti"], "velocity": ["ssti"], "thymeleaf": ["ssti"],
    "jinja2": ["ssti"], "flask": ["ssti"], "django": ["sqli", "ssti"], "twig": ["ssti"],
    "ruby": ["ssti"], "rails": ["ssti", "sqli"], "erb": ["ssti"],
    "graphql": ["graphql"], "ldap": ["ldapi"], "activedirectory": ["ldapi"],
    "asp.net": ["sqli", "xxe"], "aspnet": ["sqli", "xxe"], "iis": ["xxe"],
    "saml": ["saml"], "oauth": ["oauth"], "oidc": ["oauth"],
}

# (vuln_class, tech) → payload SUBSTRINGS to float to the front when that tech is present.
_PAYLOAD_HINTS: Dict[str, Dict[str, List[str]]] = {
    "sqli": {"mysql": ["SLEEP", "@@version"], "mariadb": ["SLEEP"],
             "postgres": ["version()", "pg_sleep"], "postgresql": ["version()", "pg_sleep"],
             "mssql": ["xp_dirtree", "WAITFOR"]},
    "ssti": {"jinja2": ["{{7*7}}"], "flask": ["{{7*7}}"], "twig": ["{{7*7}}"],
             "freemarker": ["${7*7}"], "velocity": ["${7*7}"], "thymeleaf": ["#{7*7}"],
             "ruby": ["#{7*7}"], "erb": ["<%= 7*7 %>"]},
    "lfi": {"php": ["php://filter"]},
}


def _normalize(fingerprint) -> List[str]:
    if isinstance(fingerprint, str):
        toks = [t.strip().lower() for t in fingerprint.replace(",", " ").split()]
    else:
        toks = [str(t).strip().lower() for t in (fingerprint or [])]
    return [t for t in toks if t]


class FingerprintPayloadSelector:
    def recommend_classes(self, fingerprint) -> List[Dict]:
        """Ordered vuln classes worth testing for this stack, each with the techs that justify it."""
        techs = _normalize(fingerprint)
        by_class: Dict[str, List[str]] = {}
        for t in techs:
            for vc in _TECH_CLASSES.get(t, []):
                by_class.setdefault(vc, [])
                if t not in by_class[vc]:
                    by_class[vc].append(t)
        ranked = sorted(by_class.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        return [{"vuln_class": vc, "reason": f"stack signals: {', '.join(ts)}", "techs": ts}
                for vc, ts in ranked]

    def prioritize_payloads(self, vuln_class: str, fingerprint, payloads: List[str]) -> List[str]:
        """Reorder payload values so stack-relevant ones come first (stable; adds nothing new)."""
        techs = set(_normalize(fingerprint))
        hints = _PAYLOAD_HINTS.get(vuln_class.lower(), {})
        wanted = [sub for t, subs in hints.items() if t in techs for sub in subs]
        if not wanted:
            return list(payloads)
        preferred = [p for p in payloads if any(w in p for w in wanted)]
        rest = [p for p in payloads if p not in preferred]
        return preferred + rest

    def plan(self, fingerprint) -> Dict:
        techs = _normalize(fingerprint)
        classes = self.recommend_classes(techs)
        return {"fingerprint": techs, "recommended_classes": classes,
                "class_count": len(classes),
                "note": "test the recommended classes first; pass the same fingerprint to the scanner "
                        "to float stack-relevant payloads to the front",
                "advisory": True}
