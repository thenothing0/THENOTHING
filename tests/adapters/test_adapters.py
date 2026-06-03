"""Phase K — Adapter framework, sandboxed runtime, health learning, exercise metrics,
selection, runtime analytics. Deterministic, offline, no execution, no wiki mutation."""

import pytest

import hydra.knowledge.confidence as confidence_mod
import hydra.knowledge.promotion as promotion_mod
from hydra.adapters.adapter_registry import (
    SAFE_PROFILES,
    UNSUPPORTED_PROFILES,
    AdapterRegistry,
    ProfileError,
    make_adapter_id,
    validate_profile,
)
from hydra.adapters.intelligence import (
    AdapterIntelligence,
    CapabilityExerciseAnalyzer,
    RuntimeAnalytics,
)
from hydra.adapters.runtime import AdapterRuntimeError, SandboxedAdapterRuntime
from hydra.adapters.selection import AdapterSelector
from hydra.adapters.tool_health import (
    EV_EXECUTION,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    OUTCOME_TIMEOUT,
    ToolHealthStore,
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_TOOL_HEALTH_DB", str(tmp_path / "h.db"))
    monkeypatch.setenv("HYDRA_SOURCE_LEARNING_DB", str(tmp_path / "l.db"))
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "v.db"))


@pytest.fixture
def reg():
    return AdapterRegistry().load()


# ── registry / definitions ──────────────────────────────────────────────────────
def test_deterministic_adapter_ids(reg):
    a = [x.adapter_id for x in AdapterRegistry().load().all_adapters()]
    b = [x.adapter_id for x in AdapterRegistry().load().all_adapters()]
    assert a == b and a == sorted(a)
    assert make_adapter_id("port_scanning", "nmap") == "port_scanning::nmap"


def test_every_capability_has_an_adapter(reg):
    cov = reg.adapter_coverage()
    assert cov["capabilities_with_adapter"] == cov["total_capabilities"] == 87
    assert cov["total_adapters"] >= 87


def test_adapter_definition_fields(reg):
    a = reg.get_adapter("port_scanning::nmap")
    d = a.to_dict()
    for k in ("adapter_id", "capability_id", "tool_name", "category", "execution_profile",
              "version", "health_status", "timeout_seconds", "offline_supported",
              "validation_supported", "simulation_supported", "confidence_weight",
              "supported_inputs", "supported_outputs"):
        assert k in d
    assert a.simulation_supported is True
    assert a.execution_profile in SAFE_PROFILES


def test_profiles_are_only_safe(reg):
    assert set(reg.supported_profiles()) == set(SAFE_PROFILES)
    for a in reg.all_adapters():
        assert a.execution_profile in SAFE_PROFILES


def test_unsupported_profile_rejected():
    for p in UNSUPPORTED_PROFILES:
        with pytest.raises(ProfileError):
            validate_profile(p)
    with pytest.raises(ProfileError):
        validate_profile("nonsense")
    for p in SAFE_PROFILES:
        assert validate_profile(p) == p


def test_override_with_unsupported_profile_fails(tmp_path):
    cfg = tmp_path / "adapter_catalog.yaml"
    cfg.write_text(
        "profiles: {safe: [offline], unsupported: [weaponized]}\n"
        "category_defaults: {}\n"
        "overrides: {'port_scanning::nmap': {execution_profile: weaponized}}\n",
        encoding="utf-8")
    with pytest.raises(ProfileError):
        AdapterRegistry(config_path=cfg).load()


# ── sandboxed runtime (no execution, ever) ────────────────────────────────────────
def test_runtime_never_executes(reg):
    rt = SandboxedAdapterRuntime(reg, ToolHealthStore())
    r = rt.dry_run("port_scanning::nmap", {"target": "x", "scope": []})
    assert r.executed is False and r.plan["would_execute"] is False
    assert r.outcome == OUTCOME_SUCCESS


def test_runtime_output_normalization(reg):
    rt = SandboxedAdapterRuntime(reg, ToolHealthStore())
    r = rt.simulate("port_scanning::nmap", {"target": "x", "scope": []})
    # reconnaissance output schema → assets(list)/count(int), synthetic defaults
    assert r.output == {"assets": [], "count": 0}
    assert r.executed is False


def test_runtime_input_validation(reg):
    rt = SandboxedAdapterRuntime(reg, ToolHealthStore())
    r = rt.validate("port_scanning::nmap", {})
    assert r.ok is False and r.missing_inputs == ["scope", "target"]
    r2 = rt.validate("port_scanning::nmap", {"target": "x", "scope": []})
    assert r2.ok is True and r2.missing_inputs == []


def test_runtime_unknown_adapter(reg):
    rt = SandboxedAdapterRuntime(reg, ToolHealthStore())
    with pytest.raises(AdapterRuntimeError):
        rt.dry_run("does::not-exist")


def test_runtime_accounting(reg):
    hs = ToolHealthStore()
    rt = SandboxedAdapterRuntime(reg, hs)
    aid = "port_scanning::nmap"
    rt.dry_run(aid, {"target": "x", "scope": []})
    rt.simulate(aid, {"target": "x", "scope": []})
    rt.validate(aid, {"target": "x", "scope": []})
    h = hs.health(aid)
    assert h.executions == 1 and h.simulations == 1 and h.validations == 1
    assert h.successes == 3


def test_runtime_timeout_tracking(reg):
    # Inject a clock that jumps well past the adapter's timeout → timeout outcome.
    seq = iter([0.0, 10_000.0, 20_000.0, 30_000.0])
    rt = SandboxedAdapterRuntime(reg, ToolHealthStore(), clock=lambda: next(seq))
    r = rt.dry_run("port_scanning::nmap", {"target": "x", "scope": []})
    assert r.outcome == OUTCOME_TIMEOUT


# ── tool health learning (event-sourced, rebuildable) ─────────────────────────────
def test_health_metrics_and_rebuild_identical():
    hs = ToolHealthStore()
    aid = "web_crawling::katana"
    for _ in range(7):
        hs.record(aid, EV_EXECUTION, OUTCOME_SUCCESS, runtime_ms=100.0)
    hs.record(aid, EV_EXECUTION, OUTCOME_FAILURE, runtime_ms=50.0)
    hs.record(aid, EV_EXECUTION, OUTCOME_TIMEOUT, runtime_ms=99999.0)
    h = hs.health(aid)
    assert h.successes == 7 and h.failures == 1 and h.timeout_count == 1
    assert h.total_outcomes == 9
    assert 0.0 < h.success_rate < 1.0
    assert h.reliability_score == round(8 / 11, 4)
    a = [x.to_dict() for x in hs.all_health()]
    b = [x.to_dict() for x in hs.all_health()]
    assert a == b, "health metrics must be rebuild-identical (pure over events)"


def test_health_idempotent_dedup():
    hs = ToolHealthStore()
    assert hs.record("a::b", EV_EXECUTION, OUTCOME_SUCCESS, dedup_key="k1") is True
    assert hs.record("a::b", EV_EXECUTION, OUTCOME_SUCCESS, dedup_key="k1") is False
    assert hs.health("a::b").executions == 1


def test_health_rejects_bad_event_outcome():
    hs = ToolHealthStore()
    with pytest.raises(ValueError):
        hs.record("a::b", "bogus", OUTCOME_SUCCESS)
    with pytest.raises(ValueError):
        hs.record("a::b", EV_EXECUTION, "bogus")


# ── deterministic selection ───────────────────────────────────────────────────────
def test_deterministic_adapter_selection(reg):
    r1 = [s.adapter_id for s in AdapterSelector(reg, now=1000.0).rank("port_scanning")]
    r2 = [s.adapter_id for s in AdapterSelector(reg, now=1000.0).rank("port_scanning")]
    assert r1 == r2
    best = AdapterSelector(reg, now=1000.0).select("port_scanning")
    assert best.adapter_id == r1[0]


def test_selection_reflects_health(reg):
    hs = ToolHealthStore()
    # Make nmap highly reliable; masscan unreliable.
    for _ in range(20):
        hs.record("port_scanning::nmap", EV_EXECUTION, OUTCOME_SUCCESS, runtime_ms=10.0)
    for _ in range(20):
        hs.record("port_scanning::masscan", EV_EXECUTION, OUTCOME_FAILURE, runtime_ms=10.0)
    ranked = AdapterSelector(reg, health=hs, now=1000.0).rank("port_scanning")
    ids = [s.adapter_id for s in ranked]
    assert ids.index("port_scanning::nmap") < ids.index("port_scanning::masscan")


def test_selection_unknown_capability(reg):
    with pytest.raises(KeyError):
        AdapterSelector(reg).rank("nope")


# ── capability exercise metrics (closes Phase-J blind spot) ───────────────────────
def test_capability_exercise_coverage(reg):
    rep = CapabilityExerciseAnalyzer(registry=reg).report().to_dict()
    assert rep["total_capabilities"] == 87
    assert rep["adapter_coverage_pct"] == 100.0      # every capability has an adapter
    assert rep["exercise_coverage_pct"] == 0.0       # nothing exercised yet
    assert len(rep["unexercised_capabilities"]) == 87


def test_capability_exercise_after_activity(reg):
    hs = ToolHealthStore()
    SandboxedAdapterRuntime(reg, hs).dry_run("port_scanning::nmap", {"target": "x", "scope": []})
    rep = CapabilityExerciseAnalyzer(registry=reg, health=hs).report().to_dict()
    assert rep["exercised"] >= 1
    assert "port_scanning" not in rep["unexercised_capabilities"]


# ── intelligence + runtime analytics ──────────────────────────────────────────────
def test_adapter_intelligence(reg):
    hs = ToolHealthStore()
    for _ in range(5):
        hs.record("port_scanning::nmap", EV_EXECUTION, OUTCOME_SUCCESS, runtime_ms=10.0)
    hs.record("port_scanning::masscan", EV_EXECUTION, OUTCOME_FAILURE, runtime_ms=10.0)
    hs.record("port_scanning::naabu", EV_EXECUTION, OUTCOME_TIMEOUT, runtime_ms=10.0)
    ai = AdapterIntelligence(reg, hs)
    assert ai.healthiest_adapters()[0]["adapter_id"] == "port_scanning::nmap"
    assert ai.adapter_failures()[0]["adapter_id"] == "port_scanning::masscan"
    assert ai.adapter_timeouts()[0]["adapter_id"] == "port_scanning::naabu"
    s = ai.adapter_summary()
    assert s["adapters_with_events"] == 3 and s["total_executions"] == 7


def test_runtime_analytics(reg):
    hs = ToolHealthStore()
    SandboxedAdapterRuntime(reg, hs).simulate("web_crawling::katana", {"url": "x", "params": []})
    out = RuntimeAnalytics(reg, hs).report()
    assert out["execution_profile_distribution"]  # offline/passive/validation present
    assert sum(out["execution_profile_distribution"].values()) == reg.count()
    assert out["adapters_with_events"] == 1
    assert "category_coverage" in out


# ── invariants: no promotion/confidence mutation ──────────────────────────────────
def test_promotion_confidence_untouched(reg):
    hs = ToolHealthStore()
    rt = SandboxedAdapterRuntime(reg, hs)
    rt.dry_run("port_scanning::nmap", {"target": "x", "scope": []})
    AdapterSelector(reg, health=hs).rank("port_scanning")
    # confidence engine still behaves exactly as before
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
    # promotion module forbidden-transitions table intact
    assert hasattr(promotion_mod, "FORBIDDEN_PROMOTIONS")
