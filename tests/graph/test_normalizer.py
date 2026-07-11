"""Tests for EntityNormalizer — per-type normalization and duplicate detection."""

import pytest

from hydra.graph.models import EntityType, Node
from hydra.graph.normalizer import EntityNormalizer


@pytest.fixture()
def norm():
    return EntityNormalizer()


# ── domain ──────────────────────────────────────────────────────

class TestNormalizeDomain:
    def test_lowercase(self, norm):
        assert norm.normalize_domain("EXAMPLE.COM") == "example.com"

    def test_strip_trailing_dot(self, norm):
        assert norm.normalize_domain("example.com.") == "example.com"

    def test_strip_www(self, norm):
        assert norm.normalize_domain("www.example.com") == "example.com"

    def test_strip_protocol(self, norm):
        assert norm.normalize_domain("https://example.com/path") == "example.com"

    def test_combined(self, norm):
        assert norm.normalize_domain("HTTP://WWW.Example.COM.") == "example.com"


# ── IP ──────────────────────────────────────────────────────────

class TestNormalizeIP:
    def test_ipv4_canonical(self, norm):
        assert norm.normalize_ip("  192.168.1.1  ") == "192.168.1.1"

    def test_ipv6_canonical(self, norm):
        result = norm.normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001")
        assert result == "2001:db8::1"

    def test_ipv4_mapped_v6(self, norm):
        result = norm.normalize_ip("::ffff:192.168.1.1")
        assert result == "192.168.1.1"

    def test_invalid_falls_back(self, norm):
        assert norm.normalize_ip("not-an-ip") == "not-an-ip"


# ── URL ─────────────────────────────────────────────────────────

class TestNormalizeURL:
    def test_lowercase_scheme_host(self, norm):
        result = norm.normalize_url("HTTPS://EXAMPLE.COM/Path")
        assert "example.com" in result
        assert result.startswith("https://")

    def test_sort_query_params(self, norm):
        result = norm.normalize_url("https://x.com/p?z=1&a=2")
        assert "a=2" in result
        assert result.index("a=2") < result.index("z=1")

    def test_strip_trailing_slash(self, norm):
        result = norm.normalize_url("https://example.com/")
        assert result == "https://example.com/"  # root path stays

    def test_strip_default_port_443(self, norm):
        result = norm.normalize_url("https://example.com:443/path")
        assert ":443" not in result

    def test_strip_default_port_80(self, norm):
        result = norm.normalize_url("http://example.com:80/path")
        assert ":80" not in result

    def test_preserves_path(self, norm):
        result = norm.normalize_url("https://example.com/api/v1/users")
        assert "/api/v1/users" in result

    def test_preserves_non_default_port(self, norm):
        result = norm.normalize_url("https://example.com:8443/path")
        assert ":8443" in result


# ── host ────────────────────────────────────────────────────────

class TestNormalizeHost:
    def test_with_port(self, norm):
        assert norm.normalize_host("Example.COM:8080") == "example.com:8080"

    def test_strip_protocol(self, norm):
        assert norm.normalize_host("https://Example.COM/path") == "example.com"


# ── CVE / CWE / CAPEC ──────────────────────────────────────────

class TestNormalizeCVE:
    def test_uppercase(self, norm):
        assert norm.normalize_cve("cve-2024-1234") == "CVE-2024-1234"

    def test_add_prefix(self, norm):
        assert norm.normalize_cve("2024-5678") == "CVE-2024-5678"


class TestNormalizeCWE:
    def test_format(self, norm):
        assert norm.normalize_cwe("cwe-89") == "CWE-89"

    def test_extract_number(self, norm):
        assert norm.normalize_cwe("CWE 79") == "CWE-79"


class TestNormalizeCAPEC:
    def test_format(self, norm):
        assert norm.normalize_capec("capec-66") == "CAPEC-66"


# ── generic ─────────────────────────────────────────────────────

def test_normalize_generic(norm):
    assert norm.normalize_generic("  Some Thing  ") == "some thing"


# ── dispatch ────────────────────────────────────────────────────

class TestDispatch:
    def test_dispatch_domain(self, norm):
        assert norm.normalize_id(EntityType.DOMAIN, "WWW.X.COM.") == "x.com"

    def test_dispatch_ip(self, norm):
        assert norm.normalize_id(EntityType.IP, "::ffff:10.0.0.1") == "10.0.0.1"

    def test_dispatch_cve(self, norm):
        assert norm.normalize_id(EntityType.CVE, "cve-2024-1") == "CVE-2024-1"

    def test_dispatch_unknown_type(self, norm):
        assert norm.normalize_id(EntityType.MALWARE, "  FooBar ") == "foobar"


# ── duplicate detection ────────────────────────────────────────

class TestDuplicateDetection:
    def test_finds_duplicates(self, norm):
        nodes = [
            Node(id="www.example.com", type=EntityType.DOMAIN, name="www.example.com"),
            Node(id="example.com", type=EntityType.DOMAIN, name="example.com"),
        ]
        dupes = norm.find_duplicates(nodes)
        assert len(dupes) == 1

    def test_empty_list(self, norm):
        assert norm.find_duplicates([]) == []

    def test_no_duplicates(self, norm):
        nodes = [
            Node(id="a.com", type=EntityType.DOMAIN, name="a.com"),
            Node(id="b.com", type=EntityType.DOMAIN, name="b.com"),
        ]
        assert norm.find_duplicates(nodes) == []

    def test_merge_duplicates_count(self, norm):
        from hydra.graph.knowledge_graph import KnowledgeGraph
        g = KnowledgeGraph(normalize=False)
        g.add_node(Node(id="www.a.com", type=EntityType.DOMAIN, name="www.a.com", confidence=0.3))
        g.add_node(Node(id="a.com", type=EntityType.DOMAIN, name="a.com", confidence=0.8))
        count = norm.merge_duplicates(g)
        assert count == 1
        assert g.node_count() == 1

    def test_merge_duplicates_higher_confidence_wins(self, norm):
        from hydra.graph.knowledge_graph import KnowledgeGraph
        g = KnowledgeGraph(normalize=False)
        g.add_node(Node(id="www.x.com", type=EntityType.DOMAIN, name="www.x.com", confidence=0.9))
        g.add_node(Node(id="x.com", type=EntityType.DOMAIN, name="x.com", confidence=0.3))
        norm.merge_duplicates(g)
        remaining = g.all_nodes()[0]
        assert remaining.confidence == 0.9
