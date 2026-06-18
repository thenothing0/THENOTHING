"""Session resume/compaction: parse, merge, recap, crash-safe persistence, redaction."""

from hydra.session import (
    SessionMemory,
    SessionStore,
    compact_messages,
    format_recap,
    merge_memory,
)

SUMMARY = """# Current objective
- Test orders API for IDOR
# Findings and evidence
- IDOR on /api/orders/{id} confirmed
# Open TODOs
- Check /api/invoices next
"""


def test_merge_parses_sections():
    mem = merge_memory(None, SUMMARY)
    assert "Test orders API for IDOR" in mem.objectives
    assert any("IDOR on /api/orders" in f for f in mem.findings)
    assert any("invoices" in t for t in mem.todos)
    assert mem.compactions == 1


def test_merge_dedups_and_accumulates():
    mem = merge_memory(None, SUMMARY)
    mem = merge_memory(mem, SUMMARY)            # same content again
    assert mem.objectives.count("Test orders API for IDOR") == 1   # deduped
    assert mem.compactions == 2                                    # but counted


def test_compact_messages_redacts_and_bounds():
    msgs = [{"role": "user", "content": "creds https://u:p4ssword@h/x"}]
    blob = compact_messages(msgs, max_chars=1000)
    assert "p4ssword" not in blob


def test_recap_renders():
    mem = merge_memory(None, SUMMARY)
    recap = format_recap(mem)
    assert "Resume recap" in recap and "IDOR" in recap


def test_save_load_roundtrip_and_redaction(tmp_path):
    s = SessionStore("sess1", base_dir=str(tmp_path))
    mem = merge_memory(None, SUMMARY)
    s.save([{"role": "user", "content": "token AKIAIOSFODNN7EXAMPLE"}], mem, target="example.com")
    assert s.exists()
    loaded = s.load()
    assert loaded["target"] == "example.com"
    assert isinstance(loaded["memory"], SessionMemory)
    assert loaded["memory"].compactions == 1
    assert "AKIAIOSFODNN7EXAMPLE" not in loaded["messages"][0]["content"]  # redacted on persist


def test_clear(tmp_path):
    s = SessionStore("sess2", base_dir=str(tmp_path))
    s.save([], None)
    s.clear()
    assert not s.exists()
