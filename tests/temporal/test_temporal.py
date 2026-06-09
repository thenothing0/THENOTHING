"""Phase O — Temporal Knowledge Intelligence.

Deterministic, offline, derived-only, advisory. Proves the temporal layer is built entirely
from existing derived event logs, is rebuild-identical under an injected `now`, integrates
read-only with governance, and never touches promotion.py / confidence.py / the canonical wiki.
"""

import json
import sqlite3

import pytest

import hydra.knowledge.confidence as confidence_mod
import hydra.knowledge.promotion as promotion_mod
from hydra.temporal_intel.anomaly import TemporalAnomalyDetector
from hydra.temporal_intel.context import TemporalContext
from hydra.temporal_intel.decay import DecayAnalyzer
from hydra.temporal_intel.forecast import TemporalForecastEngine
from hydra.temporal_intel.intelligence import TemporalIntelligence
from hydra.temporal_intel.store import KIND_OBSERVATION, TemporalStore
from hydra.temporal_intel.trends import MomentumAnalyzer, TrendAnalyzer
from hydra.temporal_intel.util import DEFAULT_WINDOW, classify_trend, forecast, slope

DAY = 86_400.0
WINDOW = DEFAULT_WINDOW          # 30
NOW = 200 * DAY                  # all event timestamps stay positive


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    for env, fname in [("HYDRA_TOOL_HEALTH_DB", "th.db"),
                       ("HYDRA_VERIFICATION_DB", "v.db"),
                       ("HYDRA_SOURCE_LEARNING_DB", "s.db"),
                       ("HYDRA_PLUGIN_HEALTH_DB", "p.db"),
                       ("HYDRA_DECISION_DB", "d.db"),
                       ("HYDRA_FEDERATION_DB", "f.db"),
                       ("HYDRA_TEMPORAL_DB", "t.db"),
                       ("HYDRA_WIKI_DIR", "wiki")]:
        monkeypatch.setenv(env, str(tmp_path / fname))


# ── seeding (writes timestamped events straight into the derived event logs) ─────
def _ts(bucket: int, now: float = NOW) -> float:
    """Timestamp landing in bucket index `bucket` (0 = oldest in-window, WINDOW-1 = newest)."""
    return now - (WINDOW - 1 - bucket) * DAY


def _health_conn():
    from hydra.adapters.tool_health import ToolHealthStore
    ToolHealthStore()                       # ensure schema
    import os
    return sqlite3.connect(os.environ["HYDRA_TOOL_HEALTH_DB"])


def seed_capability(bucket_counts: dict, cap: str, outcome: str = "success"):
    """bucket_counts: {bucket_index: n_events}. Writes health_events for cap + its adapter."""
    con = _health_conn()
    for b, n in bucket_counts.items():
        for i in range(n):
            con.execute(
                "INSERT OR IGNORE INTO health_events(adapter_id,capability_id,category,"
                "event_type,outcome,runtime_ms,dedup_key,occurred_at) VALUES (?,?,?,?,?,?,?,?)",
                (f"{cap}::t1", cap, "web", "execution", outcome, 1.0,
                 f"{cap}-{b}-{i}", _ts(b)))
    con.commit()
    con.close()


def _ctx():
    return TemporalContext().load()


# ── trend detection: growth / decline / stagnation ───────────────────────────────
def test_trend_growth_decline_stagnation():
    seed_capability({b: 2 * (b - 19) for b in range(20, 30)}, "cap_rise")        # recent ramp
    seed_capability({b: 2 * (10 - b) for b in range(0, 10)}, "cap_decl")          # early only
    seed_capability({b: 3 for b in range(0, 30)}, "cap_flat")                     # constant
    rows = {t["entity"]: t for t in TrendAnalyzer(_ctx()).domain_trends("capability", now=NOW)}
    assert rows["cap_rise"]["direction"] == "rising"
    assert rows["cap_decl"]["direction"] == "declining"
    assert rows["cap_flat"]["direction"] == "stable"


def test_classify_trend_pure():
    assert classify_trend([0, 0, 1, 2, 3, 4, 5]) == "rising"
    assert classify_trend([5, 4, 3, 2, 1, 0, 0]) == "declining"
    assert classify_trend([3, 3, 3, 3, 3]) == "stable"


# ── momentum / acceleration ──────────────────────────────────────────────────────
def test_momentum_growth_vs_decline():
    seed_capability({b: 2 * (b - 19) for b in range(20, 30)}, "cap_rise")
    seed_capability({b: 2 * (10 - b) for b in range(0, 10)}, "cap_decl")
    m = {r["entity"]: r for r in MomentumAnalyzer(_ctx()).domain_momentum("capability", now=NOW)}
    assert m["cap_rise"]["growth_momentum"] > 0 and m["cap_rise"]["decline_momentum"] == 0.0
    assert m["cap_decl"]["decline_momentum"] > 0 and m["cap_decl"]["growth_momentum"] == 0.0


# ── forecasting: stable / rising / declining (deterministic, non-stochastic) ──────
def test_forecast_pure_directions():
    assert forecast([1, 1, 1, 1, 1]) == pytest.approx(1.0, abs=1e-6)              # stable
    # rising: further horizons project higher (monotonic up), driven by positive slope
    assert forecast([0, 1, 2, 3, 4], horizon=3) > forecast([0, 1, 2, 3, 4], horizon=1)
    assert forecast([4, 3, 2, 1, 0]) == 0.0                                       # declining→clamped
    assert slope([0, 1, 2, 3]) > 0 and slope([3, 2, 1, 0]) < 0


def test_forecast_engine_bounded_and_deterministic():
    seed_capability({b: 2 * (b - 19) for b in range(20, 30)}, "cap_rise")
    fc = TemporalForecastEngine(_ctx()).domain_forecast("capability", now=NOW)
    assert fc["slope"] > 0 and fc["projected_next"] >= 0
    a = TemporalForecastEngine(_ctx()).report(now=NOW)
    b = TemporalForecastEngine(_ctx()).report(now=NOW)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ── decay detection: stale entity + severity ranking ─────────────────────────────
def test_decay_detects_stale_and_ranks_severity():
    seed_capability({b: 5 for b in range(0, 3)}, "cap_very_stale")     # only oldest buckets
    seed_capability({b: 5 for b in range(14, 17)}, "cap_mid")          # middle
    seed_capability({b: 5 for b in range(27, 30)}, "cap_fresh")        # recent → not decaying
    rep = DecayAnalyzer(_ctx()).report(now=NOW)
    sev = {f["entity"]: f["severity"] for f in rep["decay_findings"]}
    assert sev.get("cap_very_stale") == "high"
    assert "cap_fresh" not in sev                                      # recent activity excluded
    # severity ordering: high listed before medium/low
    sevs = [f["severity"] for f in rep["decay_findings"]]
    assert sevs == sorted(sevs, key=lambda s: {"high": 0, "medium": 1, "low": 2}[s])


# ── anomalies: spike / drop / inactivity ─────────────────────────────────────────
def test_anomaly_spike():
    base = {b: 1 for b in range(0, 30)}
    base[15] = 50                                                     # huge spike
    seed_capability(base, "cap_spike")
    types = {a["type"] for a in TemporalAnomalyDetector(_ctx()).domain_anomalies("capability", now=NOW)
             if a["entity"] == "cap_spike"}
    assert "spike" in types


def test_anomaly_inactivity():
    seed_capability({b: 3 for b in range(0, 20)}, "cap_quiet")        # then 10 empty buckets
    anoms = TemporalAnomalyDetector(_ctx()).domain_anomalies("capability", now=NOW)
    assert any(a["type"] == "inactivity" and a["entity"] == "cap_quiet" for a in anoms)


def test_anomaly_drop():
    base = {b: 20 for b in range(0, 30)}
    base[10] = 0                                                     # sharp drop
    seed_capability(base, "cap_drop")
    types = {a["type"] for a in TemporalAnomalyDetector(_ctx()).domain_anomalies("capability", now=NOW)
             if a["entity"] == "cap_drop"}
    assert "drop" in types


# ── determinism / rebuild-identical ──────────────────────────────────────────────
def test_summary_rebuild_identical_injected_now():
    seed_capability({b: 2 * (b - 19) for b in range(20, 30)}, "cap_rise")
    seed_capability({b: 5 for b in range(0, 3)}, "cap_stale")
    a = TemporalIntelligence().temporal_summary(now=NOW)
    b = TemporalIntelligence().temporal_summary(now=NOW)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_context_now_defaults_to_newest_event():
    seed_capability({29: 4}, "cap_x")
    ctx = _ctx()
    assert ctx.now() == _ts(29)                                     # newest event ts, not wall-clock


def test_empty_is_graceful():
    intel = TemporalIntelligence()
    assert intel.temporal_health()["temporal_health_score"] is None
    assert intel.temporal_summary()["total_events"] == 0
    assert TrendAnalyzer().domain_trends("capability") == []


# ── TemporalStore: event-sourced, idempotent, rebuildable ────────────────────────
def test_store_idempotent_and_rebuildable():
    s = TemporalStore()
    assert s.record_observation("cap", "util", 5.0, occurred_at=NOW, dedup_key="k1") is True
    assert s.record_observation("cap", "util", 5.0, occurred_at=NOW, dedup_key="k1") is False
    before = s.summary()
    s.reset()
    s.record_observation("cap", "util", 5.0, occurred_at=NOW, dedup_key="k1")
    assert s.summary() == before
    assert s.records(kind=KIND_OBSERVATION)[0].metric == "util"


def test_store_rejects_unknown_kind():
    with pytest.raises(ValueError):
        TemporalStore().record("mutate_wiki", "x", "m", 1.0)


# ── governance integration (read-only block) ─────────────────────────────────────
def test_governance_temporal_block_present(tmp_path):
    from hydra.knowledge.governance import GovernanceIntelligence
    block = GovernanceIntelligence().temporal_intelligence()
    assert "temporal_health_score" in block and "status" in block
    # full summary includes the block and does not raise
    summary = GovernanceIntelligence().governance_summary()
    assert "temporal_intelligence" in summary
    assert "decision_intelligence" in summary          # existing block preserved


# ── invariants ───────────────────────────────────────────────────────────────────
def test_no_wiki_mutation(tmp_path, monkeypatch):
    wiki = tmp_path / "wiki2"
    wiki.mkdir()
    monkeypatch.setenv("HYDRA_WIKI_DIR", str(wiki))
    seed_capability({b: 2 for b in range(0, 30)}, "cap_a")
    TemporalIntelligence().temporal_summary(now=NOW)
    TemporalForecastEngine().report(now=NOW)
    DecayAnalyzer().report(now=NOW)
    TemporalAnomalyDetector().report(now=NOW)
    assert list(wiki.rglob("*.md")) == []


def test_promotion_and_confidence_untouched():
    seed_capability({b: 2 for b in range(0, 30)}, "cap_a")
    TemporalIntelligence().temporal_summary(now=NOW)
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
    assert hasattr(promotion_mod, "FORBIDDEN_PROMOTIONS")


def test_context_is_read_only_to_underlying_stores():
    seed_capability({b: 2 for b in range(0, 5)}, "cap_a")
    import os
    before = sqlite3.connect(os.environ["HYDRA_TOOL_HEALTH_DB"]).execute(
        "SELECT COUNT(*) FROM health_events").fetchone()[0]
    TemporalIntelligence().temporal_summary(now=NOW)
    after = sqlite3.connect(os.environ["HYDRA_TOOL_HEALTH_DB"]).execute(
        "SELECT COUNT(*) FROM health_events").fetchone()[0]
    assert before == after          # temporal layer never writes the underlying logs
