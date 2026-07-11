#!/usr/bin/env python3
"""Stage 2 Performance Benchmark — measures HYDRA subsystem performance."""

import gc
import os
import sys
import time
import statistics

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _timeit(func, n=100, warmup=5):
    """Run func n times, return (mean_ms, median_ms, stdev_ms, min_ms, max_ms)."""
    for _ in range(warmup):
        func()
    gc.collect()
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        func()
        times.append((time.perf_counter() - t0) * 1000)
    return {
        "mean_ms": round(statistics.mean(times), 4),
        "median_ms": round(statistics.median(times), 4),
        "stdev_ms": round(statistics.stdev(times), 4) if len(times) > 1 else 0,
        "min_ms": round(min(times), 4),
        "max_ms": round(max(times), 4),
        "n": n,
    }


def bench_service_container():
    """Benchmark ServiceContainer creation + 5 service accesses."""
    from hydra.services import ServiceContainer
    from hydra.services.event_bus import EventBus

    def run():
        bus = EventBus()
        sc = ServiceContainer(bus, "/tmp/hydra_bench")
        _ = sc.system
        _ = sc.findings
        _ = sc.knowledge
        _ = sc.coverage
        _ = sc.engagement

    return _timeit(run, n=50, warmup=3)


def bench_eventbus_publish():
    """Benchmark EventBus emit — 1000 events."""
    from hydra.services.event_bus import EventBus

    bus = EventBus()
    received = []
    bus.subscribe("test.event", lambda e: received.append(1))
    bus.subscribe("test.*", lambda e: received.append(1))

    def run():
        received.clear()
        for i in range(1000):
            bus.emit("test.event", {"i": i})

    return _timeit(run, n=20, warmup=3)


def bench_eventbus_emit_none_payload():
    """Benchmark EventBus emit with None payload (empty dict allocation)."""
    from hydra.services.event_bus import EventBus

    bus = EventBus()

    def run():
        for _ in range(1000):
            bus.emit("bench.noop")

    return _timeit(run, n=50, warmup=5)


def bench_injection_points():
    """Benchmark InjectionPointFinder.find() + apply() calls."""
    from hydra.attack.injection_points import InjectionPointFinder

    finder = InjectionPointFinder()
    req = {
        "url": "https://example.com/api/v1/search?q=test&page=1&sort=asc",
        "method": "GET",
        "headers": {"User-Agent": "Mozilla/5.0", "Cookie": "sid=abc123; lang=en"},
    }

    def run():
        points = finder.find(req)
        for pt in points:
            pt.apply("FUZZ")

    return _timeit(run, n=200, warmup=10)


def bench_research_ingestion():
    """Benchmark research_ingestion regex-heavy functions."""
    from hydra.research_ingestion import ResearchIngestionEngine, ResearchSource

    engine = ResearchIngestionEngine()
    source = ResearchSource(
        source_type="writeup",
        title="Test XSS and SSRF via SSTI in WordPress",
        content="""
        This is a cross-site scripting (XSS) vulnerability found in the search parameter.
        The server-side request forgery (SSRF) allows internal network access.
        Server-side template injection (SSTI) was confirmed via {{7*7}}=49.
        SQL injection was tested but not confirmed.
        Step 1: Navigate to /search?q=<script>alert(1)</script>
        Step 2: Observe the reflected XSS in the response
        Step 3: Use the SSRF to access http://169.254.169.254/latest/meta-data/
        CVSS: 9.1 (Critical)
        CWE-79, CWE-918
        payload: '<img src=x onerror=alert(1)>'
        """ * 3,
    )

    def run():
        engine._sources.clear()
        engine._methodologies.clear()
        engine._patterns.clear()
        engine._ingestion_stats.clear()
        engine.ingest(source)

    return _timeit(run, n=200, warmup=10)


def bench_scope_extract():
    """Benchmark scope domain/wildcard extraction."""
    from hydra.scope import ProgramAdapter

    class _Stub(ProgramAdapter):
        async def fetch_program(self, pid): pass
        async def parse_scope(self, raw): pass

    adapter = _Stub()
    text = """
    In scope: *.example.com, api.example.com, staging.example.com,
    app.example.io, *.test.example.org, admin.panel.example.net,
    *.cloud.example.co, mobile.example.app, cdn.example.com
    """ * 5

    def run():
        adapter._extract_domains(text)
        adapter._extract_wildcards(text)

    return _timeit(run, n=500, warmup=20)


def bench_wiki_links():
    """Benchmark WikiPage.links property access."""
    import tempfile
    from pathlib import Path
    from hydra.knowledge.wiki_store import WikiPage, NodeType

    tmpdir = tempfile.mkdtemp()
    page_path = Path(tmpdir) / "test-page.md"
    page_path.write_text(
        "---\ntitle: Test\n---\n\n"
        "Links to [[page-one]] and [[page-two]] and [[page-three]].\n"
        "Also [[page-four]] and [[page-five]].\n"
    )

    def run():
        page = WikiPage(slug="test-page", type=NodeType.FINDING, path=page_path,
                        meta={"title": "Test"}, body="")
        for _ in range(3):
            _ = page.links

    return _timeit(run, n=200, warmup=10)


def bench_extraction_fallback():
    """Benchmark ExtractionService._fallback_extract regex patterns."""
    from hydra.services.extraction import ExtractionService
    from hydra.services.event_bus import EventBus

    svc = ExtractionService(EventBus())
    content = """
    Root cause: Improper input validation in the search parameter.
    CWE-79: Cross-site Scripting
    Step 1: Navigate to the vulnerable endpoint
    Step 2: Inject payload into q parameter
    Step 3: Observe script execution
    Impact: Account takeover via session hijacking.
    TA0001 T1190 T1059.007
    {"key": "value", "nested": {"inner": true}}
    """

    def run():
        svc._fallback_extract(content, "Extract root cause and steps and impact")

    return _timeit(run, n=500, warmup=20)


def main():
    print("=" * 70)
    print("  HYDRA v1.0.0 Stage 2 — Performance Benchmark")
    print("=" * 70)
    print()

    benchmarks = [
        ("ServiceContainer (create + 5 svc)", bench_service_container),
        ("EventBus publish (1000 events)", bench_eventbus_publish),
        ("EventBus emit None payload (1000)", bench_eventbus_emit_none_payload),
        ("InjectionPoints find+apply", bench_injection_points),
        ("ResearchIngestion ingest", bench_research_ingestion),
        ("Scope extract domains/wildcards", bench_scope_extract),
        ("WikiPage.links (3 accesses)", bench_wiki_links),
        ("Extraction fallback regex", bench_extraction_fallback),
    ]

    results = {}
    for name, func in benchmarks:
        print(f"  Running: {name} ...", end="", flush=True)
        try:
            r = func()
            results[name] = r
            print(f"  {r['mean_ms']:.3f} ms (median {r['median_ms']:.3f}, n={r['n']})")
        except Exception as e:
            print(f"  ERROR: {e}")
            results[name] = {"error": str(e)}

    print()
    print("-" * 70)
    print(f"{'Benchmark':<42} {'Mean ms':>10} {'Median ms':>10} {'Stdev':>8}")
    print("-" * 70)
    for name, r in results.items():
        if "error" in r:
            print(f"{name:<42} {'ERROR':>10}")
        else:
            print(f"{name:<42} {r['mean_ms']:>10.3f} {r['median_ms']:>10.3f} {r['stdev_ms']:>8.3f}")
    print("-" * 70)
    print()
    return results


if __name__ == "__main__":
    main()
