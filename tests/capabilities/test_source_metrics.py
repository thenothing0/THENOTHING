"""SourceMetricsStore tests (Phase C.5) — derived, keyed by stable source.id."""

import pytest

from hydra.capabilities.source_metrics import SourceMetrics, SourceMetricsStore


def _store(tmp_path):
    return SourceMetricsStore(tmp_path / "source_metrics.db")


def test_record_and_aggregate(tmp_path):
    s = _store(tmp_path)
    s.record_run("source.fofa", discoveries=10, unique_assets=7, duplicates=3, success=True, value=5.0)
    s.record_run("source.fofa", discoveries=6, unique_assets=2, duplicates=4, success=False, value=1.0)
    m = s.get("source.fofa")
    assert m.runs == 2
    assert m.discoveries == 16 and m.unique_assets == 9 and m.duplicates == 7
    assert m.successes == 1
    assert m.success_rate == 0.5            # 1/2
    assert m.average_value == round(6.0 / 16, 4)
    assert m.duplicate_rate == round(7 / 16, 4)


def test_keyed_by_stable_source_id(tmp_path):
    s = _store(tmp_path)
    s.record_run("source.crt_sh", discoveries=1)
    s.record_run("source.subfinder", discoveries=2)
    ids = {m.source_id for m in s.all()}
    assert ids == {"source.crt_sh", "source.subfinder"}
    assert all(m.source_id.startswith("source.") for m in s.all())


def test_requires_source_id(tmp_path):
    with pytest.raises(ValueError):
        _store(tmp_path).record_run("")


def test_reset_is_safe_derived_store(tmp_path):
    s = _store(tmp_path)
    s.record_run("source.fofa", discoveries=5)
    s.reset()
    assert s.get("source.fofa").runs == 0
    assert s.all() == []


def test_empty_source_metrics_defaults():
    m = SourceMetrics("source.x")
    assert m.success_rate == 0.0 and m.average_value == 0.0 and m.duplicate_rate == 0.0


def test_store_is_under_data_by_default():
    # the default store lives under data/ (gitignored derived artifacts), not the wiki
    s = SourceMetricsStore()
    assert s.db_path.parent.name == "data"
    assert "wiki" not in str(s.db_path)
