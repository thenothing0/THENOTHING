"""Entity normalization — deterministic ID canonicalization per entity type."""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import TYPE_CHECKING, Dict, List, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from hydra.graph.models import EntityType, Node

if TYPE_CHECKING:
    from hydra.graph.knowledge_graph import KnowledgeGraph

logger = logging.getLogger("hydra.graph.normalizer")

_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}


class EntityNormalizer:
    """Deterministic normalization rules for each EntityType."""

    _DISPATCH: Dict[EntityType, str] = {
        EntityType.DOMAIN: "normalize_domain",
        EntityType.IP: "normalize_ip",
        EntityType.URL: "normalize_url",
        EntityType.HOST: "normalize_host",
        EntityType.CVE: "normalize_cve",
        EntityType.CWE: "normalize_cwe",
        EntityType.CAPEC: "normalize_capec",
    }

    def normalize_id(self, entity_type: EntityType, raw_id: str) -> str:
        method_name = self._DISPATCH.get(entity_type)
        if method_name is None:
            return self.normalize_generic(raw_id)
        return getattr(self, method_name)(raw_id)

    # ── per-type normalizers ─────────────────────────────────

    @staticmethod
    def normalize_domain(raw: str) -> str:
        s = raw.strip().lower()
        for prefix in ("https://", "http://"):
            if s.startswith(prefix):
                s = s[len(prefix):]
        s = s.split("/", 1)[0]
        s = s.rstrip(".")
        if s.startswith("www."):
            s = s[4:]
        return s

    @staticmethod
    def normalize_ip(raw: str) -> str:
        s = raw.strip()
        try:
            addr = ipaddress.ip_address(s)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                return str(addr.ipv4_mapped)
            return str(addr)
        except ValueError:
            return s.lower()

    @staticmethod
    def normalize_url(raw: str) -> str:
        s = raw.strip()
        parsed = urlparse(s)
        scheme = (parsed.scheme or "https").lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port
        if port and _DEFAULT_PORTS.get(scheme) == port:
            port = None
        netloc = host
        if port:
            netloc = f"{host}:{port}"
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            netloc = f"{userinfo}@{netloc}"
        path = parsed.path.rstrip("/") or "/"
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(query_params.items()), doseq=True)
        return urlunparse((scheme, netloc, path, "", sorted_query, ""))

    @staticmethod
    def normalize_host(raw: str) -> str:
        s = raw.strip().lower()
        for prefix in ("https://", "http://"):
            if s.startswith(prefix):
                s = s[len(prefix):]
        s = s.split("/", 1)[0]
        s = s.rstrip(".")
        return s

    @staticmethod
    def normalize_cve(raw: str) -> str:
        s = raw.strip().upper()
        if not s.startswith("CVE-"):
            s = "CVE-" + s
        return s

    @staticmethod
    def normalize_cwe(raw: str) -> str:
        s = raw.strip().upper()
        m = re.search(r"(\d+)", s)
        if m:
            return f"CWE-{m.group(1)}"
        return s

    @staticmethod
    def normalize_capec(raw: str) -> str:
        s = raw.strip().upper()
        m = re.search(r"(\d+)", s)
        if m:
            return f"CAPEC-{m.group(1)}"
        return s

    @staticmethod
    def normalize_generic(raw: str) -> str:
        return raw.strip().lower()

    # ── duplicate detection ──────────────────────────────────

    def find_duplicates(self, nodes: List[Node]) -> List[Tuple[Node, Node]]:
        seen: Dict[str, Node] = {}
        dupes: List[Tuple[Node, Node]] = []
        for node in nodes:
            canonical = self.normalize_id(node.type, node.id)
            if canonical in seen and seen[canonical].id != node.id:
                dupes.append((seen[canonical], node))
            else:
                seen[canonical] = node
        return dupes

    def merge_duplicates(self, graph: KnowledgeGraph) -> int:
        nodes = graph.all_nodes()
        dupes = self.find_duplicates(nodes)
        merged = 0
        for keep, remove in dupes:
            keep.merge(remove)
            for edge in graph.outgoing(remove.id):
                graph.add_edge(type(edge)(
                    source=keep.id, target=edge.target,
                    relationship=edge.relationship,
                    confidence=edge.confidence,
                    evidence=list(edge.evidence),
                    provenance=list(edge.provenance),
                ))
            for edge in graph.incoming(remove.id):
                graph.add_edge(type(edge)(
                    source=edge.source, target=keep.id,
                    relationship=edge.relationship,
                    confidence=edge.confidence,
                    evidence=list(edge.evidence),
                    provenance=list(edge.provenance),
                ))
            graph.remove_node(remove.id)
            merged += 1
        return merged
