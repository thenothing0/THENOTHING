"""Burp pro: site-map bulk import, scanner issues, repeater raw, session timeline."""

from hydra.burp import CaptureStore


def test_bulk_sitemap_import():
    s = CaptureStore()
    res = s.add_bulk([
        {"method": "GET", "url": "https://t/a"},
        {"method": "POST", "url": "https://t/b", "params": ["x"]},
        {"no_url": True},                       # skipped
    ])
    assert res["imported"] == 2
    assert s.stats()["requests"] == 2


def test_scanner_issue_recorded_and_listed_without_blobs():
    s = CaptureStore()
    iss = s.add_issue("SQL Injection", "https://t/api?id=1", "high",
                      detail="error-based", request="GET /api?id=1", response="SQL syntax error")
    assert iss["severity"] == "high"
    listed = s.issues()
    assert listed[0]["name"] == "SQL Injection"
    assert "request" not in listed[0] and "response" not in listed[0]   # blobs omitted in list
    full = s.get_issue(iss["id"])
    assert full["request"] and full["response"]


def test_issue_text_is_scrubbed():
    s = CaptureStore()
    iss = s.add_issue("x\x1b]0;owned\x07", "https://t/\x1bbad", "low")
    assert "\x1b" not in iss["name"] and "\x1b" not in iss["url"]


def test_repeater_returns_raw():
    s = CaptureStore()
    s.add("GET", "https://t/x", raw="GET /x HTTP/1.1\nHost: t")
    assert "GET /x HTTP/1.1" in s.get_raw("GET", "https://t/x")
    assert s.get_raw("POST", "https://t/x") is None


def test_timeline_records_requests_and_issues_in_order():
    s = CaptureStore()
    s.add("GET", "https://t/a")
    s.add_issue("XSS", "https://t/a", "medium")
    tl = s.timeline()
    assert [e["kind"] for e in tl] == ["request", "issue"]
    assert "XSS" in tl[1]["summary"]


def test_clear_resets_all():
    s = CaptureStore()
    s.add("GET", "https://t/a")
    s.add_issue("X", "https://t/a")
    s.clear()
    assert s.stats()["requests"] == 0 and s.stats()["issues"] == 0 and s.stats()["timeline"] == 0
