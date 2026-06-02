"""Recon fusion pipeline tests (Phase A): offline fusion, dedup, Two-Signal confidence, materialization."""

from pathlib import Path

from hydra.capabilities import ExecutionPolicy
from hydra.knowledge.bridge import find_orphan_assets
from hydra.knowledge.schema import Confidence, NodeType
from hydra.knowledge.wiki_store import WikiStore
from hydra.recon_fusion import ReconFusionPipeline
from hydra.recon_fusion.normalize import dedup, normalize_host

FIXTURES = Path(__file__).resolve().parents[1] / "_doubles" / "fixtures" / "recon"


def test_normalize_host():
    assert normalize_host("HTTPS://API.Example.com:443/path") == "api.example.com"
    assert normalize_host("*.example.com") == "example.com"
    assert normalize_host("not a host") is None
    assert normalize_host("localhost") is None  # no dot


def test_dedup_groups_by_normalized_value():
    rows = [("api.example.com", "source.subfinder"),
            ("API.example.com", "source.amass"),
            ("https://api.example.com/x", "source.crt_sh")]
    grouped = dedup(rows, "subdomain")
    assert grouped["api.example.com"] == ["source.amass", "source.crt_sh", "source.subfinder"]


def test_offline_fusion_two_signal_confidence():
    """example.com fixtures: api found by 3 sources -> high; single-source -> low."""
    res = ReconFusionPipeline().run(
        "example.com", "discover_subdomains",
        ExecutionPolicy.offline(), fixtures_dirs=[FIXTURES])
    by_asset = {a.asset: a for a in res.assets}
    assert by_asset["api.example.com"].confidence == Confidence.HIGH
    assert set(by_asset["api.example.com"].sources) == {
        "source.subfinder", "source.amass", "source.assetfinder"}
    assert by_asset["dev.example.com"].confidence == Confidence.LOW
    assert by_asset["vpn.example.com"].confidence == Confidence.LOW
    # findomain has no fixture -> skipped, not run
    assert "source.findomain" in res.sources_skipped


def test_fusion_is_offline_only_by_default():
    """No network source should ever run under the default offline policy."""
    res = ReconFusionPipeline().run("example.com", "discover_subdomains",
                                    fixtures_dirs=[FIXTURES])
    for sid in res.sources_run:
        assert sid in {"source.subfinder", "source.amass",
                       "source.assetfinder", "source.findomain"}


def test_fusion_materializes_to_wiki(tmp_path):
    store_dir = tmp_path / "wiki"
    res = ReconFusionPipeline().run(
        "example.com", "discover_subdomains", ExecutionPolicy.offline(),
        fixtures_dirs=[FIXTURES], materialize=False)
    # materialize manually against a temp wiki to avoid touching the real one
    from hydra.knowledge.bridge import materialize_assets
    store = WikiStore(store_dir)
    written = materialize_assets(res.assets, store=store)
    assert written
    api = store.get("api-example-com", NodeType.ASSET)
    assert api is not None
    assert api.meta["confidence"] == "high"
    assert find_orphan_assets(store) == []


def test_unknown_capability_raises():
    import pytest
    with pytest.raises(KeyError):
        ReconFusionPipeline().run("example.com", "does_not_exist")
