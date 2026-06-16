"""
AttackMapping (Phase T) — the declarative MITRE ATT&CK knowledge object.

A static, deterministic mapping of ATT&CK Enterprise tactics + a curated technique set onto Hydra's
real capability categories and finding-types. It is a KNOWLEDGE OBJECT (like the Phase-Q 12-phase
campaign model), not a datastore: no DB, no network, no execution.

**Post-exploitation / out-of-scope guard.** Hydra is a left-of-boom reconnaissance & bug-bounty
platform. Tactics it provides no capability for — Resource Development, Execution, Persistence,
Privilege Escalation, Defense Evasion, Lateral Movement, Collection, Command and Control,
Exfiltration, Impact — are **model-only** (`advisory_model_only=True`, `hydra_coverage="none"`, zero
mapped capabilities). A technique is model-only whenever it maps to no Hydra category (e.g. Phishing,
even though Initial Access itself is partially covered). Model-only entries exist for completeness and
are NEVER treated as a coverage defect or as something Hydra executes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# ── ATT&CK Enterprise tactics: (id, name, hydra_coverage, advisory_model_only) ───────────────────
# advisory_model_only ⇒ Hydra provides NO capability and NO execution for the tactic.
_TACTICS: List[Tuple[str, str, str, bool]] = [
    ("TA0043", "Reconnaissance",        "full",    False),
    ("TA0042", "Resource Development",  "none",    True),
    ("TA0001", "Initial Access",        "partial", False),
    ("TA0002", "Execution",             "none",    True),
    ("TA0003", "Persistence",           "none",    True),
    ("TA0004", "Privilege Escalation",  "none",    True),
    ("TA0005", "Defense Evasion",       "none",    True),
    ("TA0006", "Credential Access",     "partial", False),
    ("TA0007", "Discovery",             "partial", False),
    ("TA0008", "Lateral Movement",      "none",    True),
    ("TA0009", "Collection",            "none",    True),
    ("TA0011", "Command and Control",   "none",    True),
    ("TA0010", "Exfiltration",          "none",    True),
    ("TA0040", "Impact",                "none",    True),
]

# ── Curated technique set: (id, name, tactic_id, hydra_categories, finding_types) ─────────────────
# Empty hydra_categories ⇒ model-only (Hydra provides no capability). finding_types narrows the match
# within a category; empty finding_types ⇒ any capability in the category qualifies.
_TECHNIQUES: List[Tuple[str, str, str, Tuple[str, ...], Tuple[str, ...]]] = [
    # Reconnaissance (TA0043) — Hydra's core strength
    ("T1595",     "Active Scanning",                  "TA0043", ("reconnaissance", "infrastructure"), ("open_port", "service", "live_host")),
    ("T1595.002", "Vulnerability Scanning",           "TA0043", ("web", "api", "verification"),       ("vulnerability", "sqli", "xss")),
    ("T1590",     "Gather Victim Network Information", "TA0043", ("reconnaissance", "infrastructure"), ("dns_record", "asn", "cidr", "ip")),
    ("T1590.002", "DNS",                              "TA0043", ("reconnaissance",),                  ("dns_record", "subdomain")),
    ("T1590.005", "IP Addresses",                     "TA0043", ("reconnaissance", "infrastructure"), ("ip", "cidr")),
    ("T1592",     "Gather Victim Host Information",    "TA0043", ("reconnaissance", "infrastructure"), ("technology", "banner", "host")),
    ("T1591",     "Gather Victim Org Information",     "TA0043", ("reconnaissance", "source_code"),    ("osint_profile", "whois")),
    ("T1593",     "Search Open Websites/Domains",     "TA0043", ("reconnaissance", "source_code"),    ("subdomain", "repository")),
    ("T1594",     "Search Victim-Owned Websites",     "TA0043", ("web", "reconnaissance"),            ("url", "endpoint", "path")),
    ("T1596",     "Search Open Technical Databases",  "TA0043", ("reconnaissance",),                  ("cert", "subdomain")),
    ("T1589",     "Gather Victim Identity Information","TA0043", ("reconnaissance", "source_code", "secrets"), ("email", "credential", "osint_profile")),
    # Initial Access (TA0001)
    ("T1190",     "Exploit Public-Facing Application","TA0001", ("web", "api", "verification"),       ("sqli", "xss", "ssrf", "idor", "auth_bypass", "path_traversal")),
    ("T1133",     "External Remote Services",         "TA0001", ("infrastructure",),                  ("service", "open_port")),
    ("T1078",     "Valid Accounts",                   "TA0001", ("secrets", "source_code"),           ("credential", "secret")),
    ("T1199",     "Trusted Relationship",             "TA0001", ("source_code",),                     ("supply_chain_risk", "dependency_vuln")),
    ("T1566",     "Phishing",                         "TA0001", (),                                   ()),   # model-only: Hydra does not phish
    # Credential Access (TA0006)
    ("T1552",     "Unsecured Credentials",            "TA0006", ("secrets", "source_code"),           ("secret", "credential")),
    ("T1552.001", "Credentials In Files",             "TA0006", ("source_code", "secrets"),           ("secret",)),
    ("T1552.005", "Cloud Instance Metadata API",      "TA0006", ("cloud",),                           ("cloud_metadata",)),
    ("T1110",     "Brute Force",                      "TA0006", ("web", "api"),                       ("auth_bypass", "rate_limit")),
    ("T1212",     "Exploitation for Credential Access","TA0006",("verification", "web"),              ("auth_bypass", "jwt")),
    # Discovery (TA0007)
    ("T1046",     "Network Service Discovery",        "TA0007", ("reconnaissance", "infrastructure"), ("open_port", "service", "banner")),
    ("T1526",     "Cloud Service Discovery",          "TA0007", ("cloud",),                           ("cloud_asset", "cloud_bucket")),
    ("T1087",     "Account Discovery",                "TA0007", ("api", "web"),                       ("endpoint", "auth_flow")),
    ("T1083",     "File and Directory Discovery",     "TA0007", ("web",),                             ("path", "url")),
    ("T1213",     "Data from Information Repositories","TA0007", ("source_code",),                     ("repository", "secret")),
    ("T1018",     "Remote System Discovery",          "TA0007", ("reconnaissance", "infrastructure"), ("subdomain", "internal_host", "vhost")),
    ("T1538",     "Cloud Service Dashboard",          "TA0007", ("cloud",),                           ("cloud_misconfig",)),
    # Out-of-scope / post-exploitation tactics — model-only (no Hydra capability, no execution)
    ("T1588",     "Obtain Capabilities",              "TA0042", (), ()),
    ("T1583",     "Acquire Infrastructure",           "TA0042", (), ()),
    ("T1059",     "Command and Scripting Interpreter","TA0002", (), ()),
    ("T1203",     "Exploitation for Client Execution","TA0002", (), ()),
    ("T1505",     "Server Software Component",        "TA0003", (), ()),
    ("T1068",     "Exploitation for Privilege Escalation", "TA0004", (), ()),
    ("T1070",     "Indicator Removal",                "TA0005", (), ()),
    ("T1021",     "Remote Services",                  "TA0008", (), ()),
    ("T1119",     "Automated Collection",             "TA0009", (), ()),
    ("T1071",     "Application Layer Protocol",       "TA0011", (), ()),
    ("T1041",     "Exfiltration Over C2 Channel",     "TA0010", (), ()),
    ("T1485",     "Data Destruction",                 "TA0040", (), ()),
]


@dataclass(frozen=True)
class AttackTactic:
    tactic_id: str
    name: str
    hydra_coverage: str            # full | partial | none
    advisory_model_only: bool

    def to_dict(self) -> Dict:
        return {"tactic_id": self.tactic_id, "name": self.name,
                "hydra_coverage": self.hydra_coverage,
                "advisory_model_only": self.advisory_model_only, "advisory": True}


@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str
    name: str
    tactic_id: str
    categories: Tuple[str, ...]
    finding_types: Tuple[str, ...]

    @property
    def model_only(self) -> bool:
        return not self.categories

    def to_dict(self) -> Dict:
        return {"technique_id": self.technique_id, "name": self.name,
                "tactic_id": self.tactic_id, "categories": list(self.categories),
                "finding_types": list(self.finding_types),
                "advisory_model_only": self.model_only, "advisory": True}


class AttackMapping:
    """Resolves the static ATT&CK catalog against the live capability catalog. Deterministic."""

    def __init__(self, ctx=None):
        self._ctx = ctx
        self._tactics = [AttackTactic(*t) for t in _TACTICS]
        self._techniques = [AttackTechnique(i, n, t, c, f) for (i, n, t, c, f) in _TECHNIQUES]
        self._by_tactic: Optional[Dict[str, AttackTactic]] = None
        self._caps_for: Dict[str, List[str]] = {}

    # ── catalog access (lazy; injected ctx shares the load) ──────────────────────
    def _catalog(self):
        if self._ctx is None:
            from hydra.offensive_intel.context import OffensiveContext
            self._ctx = OffensiveContext().load()
        return self._ctx.catalog()

    # ── static views ─────────────────────────────────────────────────────────────
    def tactics(self) -> List[AttackTactic]:
        return list(self._tactics)

    def techniques(self) -> List[AttackTechnique]:
        return list(self._techniques)

    def tactic(self, tactic_id: str) -> Optional[AttackTactic]:
        if self._by_tactic is None:
            self._by_tactic = {t.tactic_id: t for t in self._tactics}
        return self._by_tactic.get(tactic_id)

    def techniques_for_tactic(self, tactic_id: str) -> List[AttackTechnique]:
        return [t for t in self._techniques if t.tactic_id == tactic_id]

    def technique(self, technique_id: str) -> Optional[AttackTechnique]:
        return next((t for t in self._techniques if t.technique_id == technique_id), None)

    # ── resolution: technique → Hydra capabilities (deterministic, memoized) ─────
    def capabilities_for(self, technique: AttackTechnique) -> List[str]:
        if technique.model_only:
            return []
        if technique.technique_id in self._caps_for:
            return self._caps_for[technique.technique_id]
        cats = set(technique.categories)
        fts = set(technique.finding_types)
        out: List[str] = []
        for c in self._catalog().all():
            if c.category in cats and (not fts or (set(c.supported_finding_types) & fts)):
                out.append(c.capability_id)
        out = sorted(set(out))
        self._caps_for[technique.technique_id] = out
        return out

    def techniques_for_capability(self, capability_id: str) -> List[str]:
        out = [t.technique_id for t in self._techniques
               if not t.model_only and capability_id in self.capabilities_for(t)]
        return sorted(out)
