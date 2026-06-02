"""Capability registry tests (Phase A): loading, stable ids, categories, offline policy gating."""

import pytest

from hydra.capabilities import CapabilityRegistry, ExecutionPolicy
from hydra.capabilities.sources import Source, SourceCategory


EXPECTED_CAPABILITIES = {
    "discover_subdomains", "discover_urls", "http_probe", "dns_intelligence",
    "asn_intelligence", "cloud_asset_discovery", "repository_intelligence",
    "technology_fingerprinting", "attack_surface_mapping",
}


@pytest.fixture(scope="module")
def registry():
    return CapabilityRegistry().load()


def test_all_nine_capabilities_load(registry):
    assert set(registry.names()) == EXPECTED_CAPABILITIES


def test_every_source_has_stable_id(registry):
    for name in registry.names():
        for s in registry.get(name).sources:
            assert s.id.startswith("source."), f"{name}: {s.name} lacks a stable source.* id"


def test_declared_threat_intel_sources_present(registry):
    ids = {s.id for s in registry.get("discover_subdomains").sources}
    for sid in ("source.fofa", "source.zoomeye", "source.netlas",
                "source.binaryedge", "source.leakix"):
        assert sid in ids


def test_source_categorization_locked(registry):
    subs = {s.id: s for s in registry.get("discover_subdomains").sources}
    for sid in ("source.fofa", "source.zoomeye", "source.netlas",
                "source.binaryedge", "source.leakix"):
        assert subs[sid].category == SourceCategory.THREAT_INTELLIGENCE
    hunter = {s.id: s for s in registry.get("repository_intelligence").sources}["source.hunter"]
    assert hunter.category == SourceCategory.CONTACT_INTELLIGENCE


def test_offline_policy_admits_only_offline_capable(registry):
    off = registry.select("discover_subdomains", ExecutionPolicy.offline())
    assert all(s.offline_capable for s in off)
    assert {s.id for s in off} == {"source.subfinder", "source.amass",
                                    "source.assetfinder", "source.findomain"}


def test_online_policy_requires_keys(registry):
    # chaos requires an api key — refused online without it, admitted with it
    no_keys = registry.select("discover_subdomains", ExecutionPolicy.online())
    assert "source.chaos" not in {s.id for s in no_keys}
    with_key = registry.select("discover_subdomains",
                               ExecutionPolicy.online(available_keys={"source.chaos"}))
    assert "source.chaos" in {s.id for s in with_key}


def test_network_source_not_runnable_offline(registry):
    crt = {s.id: s for s in registry.get("discover_subdomains").sources}["source.crt_sh"]
    assert not crt.runnable(ExecutionPolicy.offline())
    assert crt.runnable(ExecutionPolicy.online())


def test_source_has_perf_block_from_day_one():
    s = Source(id="source.demo")
    for fld in ("trust_score", "discoveries", "unique_assets", "duplicates",
                "confidence_weight", "success_rate", "average_value"):
        assert hasattr(s, fld)


def test_source_requires_id():
    with pytest.raises(ValueError):
        Source(id="")
