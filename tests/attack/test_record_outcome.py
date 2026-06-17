"""
Regression: the scan→attack-memory loop-back must actually fire.

`report_builder.record_outcome` previously imported a non-existent `record_event`, so the in-scan
`record=True` learning path silently failed (swallowed by try/except). This pins the correct wiring to
`attack_memory.append_event(kind, payload)`.
"""

import hydra.skills.attack_memory as am
from hydra.attack.report_builder import record_outcome


def test_record_outcome_appends_attack_memory_event(monkeypatch):
    calls = []
    monkeypatch.setattr(am, "append_event", lambda kind, payload, **kw: calls.append((kind, payload)))
    record_outcome("acme.test", "xss", "confirmed", point="q",
                   evidence={"response": {"status": 200}})
    assert len(calls) == 1
    kind, payload = calls[0]
    assert kind == "attack_outcome"
    assert payload["target"] == "acme.test" and payload["vuln_class"] == "xss"
    assert payload["verdict"] == "confirmed" and payload["status"] == 200
