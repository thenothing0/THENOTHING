"""Phase C.5 scalability-hardening tests: bounded chains, guardrails, deferred rebuild."""

import time

import hydra.knowledge.bridge as bridge_mod
from hydra.knowledge.discovery import (
    ChainDiscovery,
    DiscoveryLimits,
    PatternDiscovery,
    confirm_candidate,
    confirm_candidates,
)
from hydra.knowledge.schema import NodeType
from hydra.knowledge.wiki_store import WikiStore

_ALLOWED_BASES = {"shared_target", "shared_asset", "shared_program", "shared_root_report"}


def _wiki(tmp_path, n_findings, n_targets):
    ws = WikiStore(tmp_path / "wiki")
    for t in range(n_targets):
        ws.upsert(NodeType.TARGET, f"t{t}", {"tags": ["t"]}, f"# t{t}\n")
    for i in range(n_findings):
        ws.upsert(NodeType.FINDING, f"f{i}",
                  {"tags": ["idor", "api"], "status": "submitted", "target": f"[[t{i % n_targets}]]"},
                  f"# f{i}\nidor escalation\n")
    return ws


# ── O(F²) removal: only bounded structured bases, no graph_path ───────────────
def test_chains_only_structured_bases(tmp_path):
    ws = _wiki(tmp_path, 30, 3)
    chains = ChainDiscovery(ws).discover()
    assert chains
    assert all(c.link_basis in _ALLOWED_BASES for c in chains)
    assert not any(c.link_basis == "graph_path" for c in chains)


def test_chain_steps_are_bounded(tmp_path):
    # one target with 50 validated findings → a single chain capped at <= 12 steps
    ws = _wiki(tmp_path, 50, 1)
    chains = ChainDiscovery(ws).discover()
    shared = next(c for c in chains if c.link_basis == "shared_target")
    assert len(shared.steps) <= 12


def test_chain_discovery_scales_linearly(tmp_path):
    """Sanity guard against an O(F²) regression: 1000 findings must finish quickly."""
    ws = _wiki(tmp_path, 1000, 40)
    start = time.perf_counter()
    ChainDiscovery(ws).discover()
    elapsed = time.perf_counter() - start
    assert elapsed < 8.0, f"ChainDiscovery too slow ({elapsed:.1f}s) — possible O(F^2) regression"


def test_shared_program_and_root_report_bases(tmp_path):
    ws = WikiStore(tmp_path / "wiki")
    ws.upsert(NodeType.REPORT, "rpt", {"tags": ["report"]}, "# report\n")
    for tgt in ("ta", "tb", "tc", "td"):
        ws.upsert(NodeType.TARGET, tgt, {"tags": ["t"]}, f"# {tgt}\n")
    # pair (1): share a PROGRAM, different targets, no report link
    for i, tgt in enumerate(("ta", "tb")):
        ws.upsert(NodeType.FINDING, f"prog{i}",
                  {"tags": ["idor"], "status": "submitted", "target": f"[[{tgt}]]",
                   "program": "bigcorp"}, f"# prog{i}\nidor\n")
    # pair (2): share a ROOT REPORT, different targets, different/absent program
    for i, tgt in enumerate(("tc", "td")):
        ws.upsert(NodeType.FINDING, f"rep{i}",
                  {"tags": ["ssrf"], "status": "submitted", "target": f"[[{tgt}]]"},
                  f"# rep{i}\nssrf; references [[rpt]]\n")
    bases = {c.link_basis for c in ChainDiscovery(ws).discover()}
    assert "shared_program" in bases
    assert "shared_root_report" in bases


# ── guardrails: deterministic truncation ─────────────────────────────────────
def test_max_candidates_truncates_deterministically(tmp_path):
    ws = _wiki(tmp_path, 60, 30)  # many shared-target groups
    limits = DiscoveryLimits(max_candidates=3)
    a = ChainDiscovery(ws).discover(limits=limits)
    b = ChainDiscovery(ws).discover(limits=limits)
    assert len(a) <= 3
    assert [c.id for c in a] == [c.id for c in b]  # deterministic


def test_max_groups_caps_work(tmp_path):
    ws = _wiki(tmp_path, 60, 30)
    full = ChainDiscovery(ws).discover(limits=DiscoveryLimits(max_groups=10000, max_candidates=10000))
    capped = ChainDiscovery(ws).discover(limits=DiscoveryLimits(max_groups=2, max_candidates=10000))
    assert len(capped) <= len(full)


def test_pattern_discovery_honors_limits(tmp_path):
    ws = _wiki(tmp_path, 20, 2)
    res = PatternDiscovery(ws).discover(limits=DiscoveryLimits(max_candidates=1))
    assert len(res) <= 1


# ── rebuild amplification eliminated ─────────────────────────────────────────
def test_single_confirm_does_not_rebuild(tmp_path, monkeypatch):
    ws = _wiki(tmp_path, 4, 1)
    calls = {"n": 0}
    orig = bridge_mod.rebuild_index
    monkeypatch.setattr(bridge_mod, "rebuild_index", lambda *a, **k: calls.__setitem__("n", calls["n"] + 1) or orig(*a, **k))
    cid = ChainDiscovery(ws).discover()[0].id
    confirm_candidate("chain", cid, ws)            # rebuild defaults to False
    assert calls["n"] == 0, "single confirm must not trigger a graph rebuild"


def test_batch_confirm_rebuilds_once(tmp_path, monkeypatch):
    ws = _wiki(tmp_path, 6, 3)  # 3 shared-target chains
    cands = ChainDiscovery(ws).discover()
    pairs = [("chain", c.id) for c in cands]
    calls = {"n": 0}
    orig = bridge_mod.rebuild_index
    monkeypatch.setattr(bridge_mod, "rebuild_index", lambda *a, **k: calls.__setitem__("n", calls["n"] + 1) or orig(*a, **k))
    out = confirm_candidates(pairs, ws)
    assert out["count"] >= 1
    assert calls["n"] == 1, f"batch confirm must rebuild exactly once, got {calls['n']}"
