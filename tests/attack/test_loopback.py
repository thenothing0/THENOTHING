"""
Knowledge-graph loop-back — end-to-end proof.

A confirmed finding is recorded as a verification SUCCESS for its vuln-class; Phase-P reads the
verification store, so the backing capabilities' effectiveness rises — which is what Phase-S/T/U build
on. This closes the gap the audit flagged (the loop-back previously terminated at findings.db). Fully
env-isolated (HYDRA_VERIFICATION_DB / HYDRA_TOOL_HEALTH_DB → tmp) so it never touches real stores.
"""



def test_confirmed_finding_feeds_phase_p_effectiveness(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "vr.db"))
    monkeypatch.setenv("HYDRA_TOOL_HEALTH_DB", str(tmp_path / "th.db"))
    from hydra.attack import FindingPublisher
    from hydra.offensive_intel.intelligence import OffensiveIntelligence

    oi0 = OffensiveIntelligence()
    cap = next(c.capability_id for c in oi0.ctx.catalog().all()
               if "xss" in c.supported_finding_types)
    before = oi0.engine.get(cap).effectiveness
    assert oi0.engine.get(cap).status == "prior_only"          # no learning yet

    pub = FindingPublisher()                                    # real verification store (isolated)
    for i in range(8):
        out = pub.publish("acme.test", [{
            "vuln_class": "xss", "verdict": "confirmed", "point": f"p{i}",
            "evidence": {"confirmation": {"families": ["reflection", "execution"]}}}])
        assert out["learned_into_intelligence"] == 1

    after = OffensiveIntelligence()                             # fresh read of the now-populated store
    ce = after.engine.get(cap)
    assert ce.effectiveness > before and ce.status == "learned"   # the loop fed Phase-P


def test_loopback_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("HYDRA_VERIFICATION_DB", str(tmp_path / "vr.db"))
    from hydra.attack import FindingPublisher
    finding = {"vuln_class": "sqli", "verdict": "confirmed", "point": "id",
               "evidence": {"confirmation": {"families": ["error", "timing"]}}}
    pub = FindingPublisher()
    first = pub.publish("acme.test", [finding])["learned_into_intelligence"]
    second = pub.publish("acme.test", [finding])["learned_into_intelligence"]   # same dedup_key
    assert first == 1 and second == 0                          # idempotent — not double-counted
