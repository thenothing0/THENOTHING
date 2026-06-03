"""Phase M — plugin framework, effective catalog, dependency graph, ownership, health.
Deterministic, offline, declarative-only, advisory, no execution / promotion / confidence / wiki."""

import textwrap

import pytest

import hydra.knowledge.confidence as confidence_mod
import hydra.knowledge.promotion as promotion_mod
from hydra.adapters.adapter_registry import AdapterRegistry
from hydra.capabilities.dependency_graph import (
    CapabilityDependencyGraph,
    DependencyIntelligence,
)
from hydra.plugins.ecosystem import CapabilityMarketplace, EcosystemAnalyzer
from hydra.plugins.health import (
    EV_CAPABILITY,
    EV_SELECTION,
    PluginHealthAnalyzer,
    PluginHealthStore,
)
from hydra.plugins.ownership import AgentOwnershipResolver
from hydra.plugins.plugin_catalog import EffectiveCapabilityCatalog
from hydra.plugins.plugin_loader import PluginLoader
from hydra.plugins.plugin_registry import PluginRegistry
from hydra.plugins.plugin_validator import PluginDefinition, PluginValidator


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_PLUGIN_HEALTH_DB", str(tmp_path / "ph.db"))


def _reg():
    """Registry over the bundled reference packs (default plugin dir)."""
    return PluginRegistry()


# ── plugin system ─────────────────────────────────────────────────────────────
def test_deterministic_loading():
    a = [p["plugin_id"] for p in PluginRegistry().list_plugins()]
    b = [p["plugin_id"] for p in PluginRegistry().list_plugins()]
    assert a == b == sorted(a)
    assert len(a) == 6 and all(not p["errors"] for p in PluginRegistry().list_plugins())


def test_effective_catalog_grows_beyond_150():
    eff = EffectiveCapabilityCatalog(_reg()).load()
    comp = eff.composition()
    assert comp["core"] == 87
    assert comp["effective"] > 150 and comp["plugin"] == comp["effective"] - 87
    assert comp["rejected_duplicates"] == 0


def test_adapters_grow_beyond_400():
    eff = EffectiveCapabilityCatalog(_reg()).load()
    assert AdapterRegistry(catalog=eff).load().count() > 400


def test_duplicate_capability_rejected(tmp_path):
    # a plugin redeclaring a CORE capability id must fail validation (globally unique)
    pd = PluginDefinition(plugin_id="dup_pack", version="1.0.0",
                          capabilities=[{"id": "port_scanning", "category": "reconnaissance",
                                         "tools": ["x"]}])
    errors = PluginRegistry().validate_plugin(pd)
    assert any("globally unique" in e for e in errors)


def test_register_and_unload_plugin(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_PLUGIN_DIR", str(tmp_path / "empty"))
    (tmp_path / "empty").mkdir()
    reg = PluginRegistry()
    assert reg.list_plugins() == []
    pd = PluginDefinition(plugin_id="x_pack", version="1.0.0",
                          capabilities=[{"id": "x_cap", "category": "web", "tools": ["t1", "t2"]}])
    assert reg.register_plugin(pd) == []                       # valid → enabled
    assert "x_cap" in {c["id"] for c in reg.plugin_capabilities()}
    assert reg.unload_plugin("x_pack") is True
    assert reg.plugin_capabilities() == []
    assert reg.load_plugin("x_pack") == []                     # re-enable


def test_version_compatibility():
    v = PluginValidator()
    bad = PluginDefinition(plugin_id="p", version="1.2")       # not semver
    assert any("version" in e for e in v.validate(bad))
    pd = PluginDefinition(plugin_id="p", version="1.0.0",
                          requires_plugins=[{"plugin_id": "base", "min_version": "2.0.0"}])
    assert any("missing required plugin" in e for e in v.check_version_compat(pd, {}))
    assert any("< required" in e for e in v.check_version_compat(pd, {"base": "1.0.0"}))
    assert v.check_version_compat(pd, {"base": "2.1.0"}) == []


def test_executable_content_rejected():
    pd = PluginDefinition(plugin_id="evil", version="1.0.0",
                          capabilities=[{"id": "c", "category": "web", "exec": "rm -rf /"}])
    assert any("forbidden key" in e for e in PluginValidator().validate(pd))


def test_loader_offline_discovery():
    plugins = PluginLoader().discover()
    assert {p.plugin_id for p in plugins} >= {"cloud_pack", "mobile_pack", "osint_pack"}


# ── dependency graph ──────────────────────────────────────────────────────────
def _graph():
    reg = _reg()
    eff = EffectiveCapabilityCatalog(reg).load()
    return CapabilityDependencyGraph(eff, reg.plugin_dependency_edges()).load()


def test_dependency_graph_acyclic_and_paths():
    g = _graph()
    assert g.detect_cycles("requires") == []                  # requires is acyclic
    assert g.dependency_paths("subdomain_discovery", "dns_resolution") == \
        ["subdomain_discovery", "dns_resolution"]
    assert g.dependency_paths("xss_probing", "http_probing")[:1] == ["xss_probing"]


def test_dependency_cycle_detection(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_PLUGIN_DIR", str(tmp_path / "p"))
    (tmp_path / "p").mkdir()
    pack = tmp_path / "p" / "cycle.yaml"
    pack.write_text(textwrap.dedent("""
        plugin_id: cycle_pack
        version: 1.0.0
        capabilities:
          - {id: cyc_a, category: web, tools: [t]}
          - {id: cyc_b, category: web, tools: [t]}
        dependencies:
          - {from: cyc_a, relation: requires, to: cyc_b}
          - {from: cyc_b, relation: requires, to: cyc_a}
    """), encoding="utf-8")
    reg = PluginRegistry()
    eff = EffectiveCapabilityCatalog(reg).load()
    g = CapabilityDependencyGraph(eff, reg.plugin_dependency_edges(),
                                  core_deps_path=tmp_path / "none.yaml").load()
    assert g.detect_cycles("requires"), "cycle must be detected"


def test_isolated_and_intelligence():
    rep = DependencyIntelligence(_graph()).report()
    assert rep["requires_acyclic"] is True
    assert rep["coverage_gaps"] == []                          # all edges resolve
    assert rep["edge_count"] > 30 and rep["critical_capabilities"]
    assert isinstance(rep["isolated_capabilities"], list)


# ── ownership ─────────────────────────────────────────────────────────────────
def test_auto_ownership_no_gaps():
    eff = EffectiveCapabilityCatalog(_reg()).load()
    res = AgentOwnershipResolver(eff).resolve()
    assert res["owned"] == res["total_capabilities"]          # every cap auto-owned
    assert res["ownership_gap_count"] == 0


def test_ownership_gap_detection():
    eff = EffectiveCapabilityCatalog(_reg()).load()
    # inject a capability in a category no agent owns → gap (without touching the catalog file)
    from hydra.capabilities.capability_catalog import CapabilityEntry
    eff._caps["weird_cap"] = CapabilityEntry(capability_id="weird_cap", category="quantum",
                                             tools=["q"])
    res = AgentOwnershipResolver(eff).resolve()
    assert "weird_cap" in res["ownership_gaps"]


def test_ownership_conflict_on_bad_preferred():
    eff = EffectiveCapabilityCatalog(_reg()).load()
    res = AgentOwnershipResolver(eff, preferred={"port_scanning": "nonexistent_agent"}).resolve()
    assert any(c["capability_id"] == "port_scanning" for c in res["ownership_conflicts"])


# ── plugin health (rebuildable, idempotent) ───────────────────────────────────
def test_plugin_health_rebuild_identical_and_idempotent():
    hs = PluginHealthStore()
    assert hs.record("cloud_pack", EV_CAPABILITY, capability_id="cloud_aws_enum", dedup_key="k1") is True
    assert hs.record("cloud_pack", EV_CAPABILITY, capability_id="cloud_aws_enum", dedup_key="k1") is False
    hs.record("cloud_pack", EV_SELECTION, capability_id="cloud_aws_enum")
    a = PluginHealthAnalyzer(_reg(), hs).report()
    b = PluginHealthAnalyzer(_reg(), hs).report()
    assert a == b
    cloud = next(p for p in a if p["plugin_id"] == "cloud_pack")
    assert cloud["distinct_capabilities"] == 1 and 0.0 <= cloud["plugin_health"] <= 1.0


# ── ecosystem intelligence ────────────────────────────────────────────────────
def test_ecosystem_and_marketplace():
    reg = _reg()
    eff = EffectiveCapabilityCatalog(reg).load()
    eco = EcosystemAnalyzer(reg, eff).report()
    assert eco["installed_plugins"] == 6
    assert eco["capabilities_added"] == 66 and eco["adapters_added"] > 200
    mk = CapabilityMarketplace(reg, eff).recommend()
    assert "weak_areas" in mk and "ecosystem_gaps" in mk


# ── invariants ────────────────────────────────────────────────────────────────
def test_core_catalog_unchanged_by_plugins():
    from hydra.capabilities.capability_catalog import CapabilityCatalog
    assert CapabilityCatalog().load().count() == 87           # core is never mutated


def test_promotion_confidence_untouched():
    EffectiveCapabilityCatalog(_reg()).load()
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
    assert hasattr(promotion_mod, "FORBIDDEN_PROMOTIONS")
