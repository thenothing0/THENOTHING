"""CaptureStore: bounded growth (M9) + control-byte scrubbing (M11)."""

from hydra.burp import CaptureStore, scrub


def test_scrub_strips_terminal_escapes_keeps_text():
    assert scrub("\x1b]0;PWNED\x07/api/x") == "]0;PWNED/api/x".replace("]0;PWNED", "]0;PWNED")
    assert "\x1b" not in scrub("\x1b[31mred\x1b[0m")
    assert scrub("ok\ttab\nnl") == "ok\ttab\nnl"  # tab/newline preserved


def test_requests_are_bounded_lru():
    s = CaptureStore(max_requests=10)
    for i in range(50):
        s.add("GET", f"https://t/{i}")
    assert s.stats()["requests"] == 10
    urls = [r["url"] for r in s.requests(limit=100)]
    assert "https://t/49" in urls and "https://t/0" not in urls  # newest kept, oldest evicted


def test_endpoints_and_params_bounded():
    s = CaptureStore(max_endpoints=5, max_params=3)
    for i in range(20):
        s.add("GET", f"https://t/ep/{i}", params=[f"p{j}" for j in range(10)])
    assert s.stats()["endpoints"] == 5
    for ep in s.endpoints():
        assert len(ep["params"]) <= 3


def test_ingested_url_is_scrubbed():
    s = CaptureStore()
    s.add("GET", "https://t/\x1b]0;owned\x07x")
    assert all("\x1b" not in r["url"] for r in s.requests())
