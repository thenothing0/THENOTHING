"""Stage 3 — Production Observability test suite.

Covers: structured logging, telemetry, crash diagnostics, health registry,
resource monitor, and wiring into dispatcher / services / monitor / event_bus.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
import unittest
from unittest.mock import patch

from hydra.observability.logging import (
    CorrelationFilter,
    JSONFormatter,
    configure_logging,
    get_correlation_id,
    set_correlation_id,
)
from hydra.observability.telemetry import Telemetry, telemetry
from hydra.observability.diagnostics import DiagnosticCapture, diagnostics
from hydra.observability.health import HealthRegistry, health
from hydra.observability.resources import ResourceMonitor, resources


# ── Structured Logging ──────────────────────────────────────────────────


class TestCorrelationId(unittest.TestCase):
    def test_set_and_get(self):
        cid = set_correlation_id("abc123")
        self.assertEqual(cid, "abc123")
        self.assertEqual(get_correlation_id(), "abc123")

    def test_auto_generate(self):
        cid = set_correlation_id()
        self.assertTrue(len(cid) == 12)
        self.assertEqual(get_correlation_id(), cid)

    def test_explicit_none_generates(self):
        cid = set_correlation_id(None)
        self.assertTrue(len(cid) > 0)


class TestCorrelationFilter(unittest.TestCase):
    def test_injects_correlation_id(self):
        set_correlation_id("test-cid")
        filt = CorrelationFilter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
        result = filt.filter(record)
        self.assertTrue(result)
        self.assertEqual(record.correlation_id, "test-cid")  # type: ignore[attr-defined]


class TestJSONFormatter(unittest.TestCase):
    def test_format_produces_valid_json(self):
        set_correlation_id("json-test")
        filt = CorrelationFilter()
        fmt = JSONFormatter()
        record = logging.LogRecord("test.logger", logging.WARNING, "file.py", 42, "hello %s", ("world",), None)
        filt.filter(record)
        output = fmt.format(record)
        parsed = json.loads(output)
        self.assertEqual(parsed["level"], "WARNING")
        self.assertEqual(parsed["logger"], "test.logger")
        self.assertEqual(parsed["message"], "hello world")
        self.assertEqual(parsed["correlation_id"], "json-test")
        self.assertEqual(parsed["line"], 42)
        self.assertIn("timestamp", parsed)

    def test_format_with_exception(self):
        fmt = JSONFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            record = logging.LogRecord("test", logging.ERROR, "", 0, "fail", (), sys.exc_info())
        output = fmt.format(record)
        parsed = json.loads(output)
        self.assertIn("exception", parsed)
        self.assertIn("ValueError", parsed["exception"])


class TestConfigureLogging(unittest.TestCase):
    def test_installs_filter_on_root(self):
        root = logging.getLogger()
        initial_filter_count = len(root.filters)
        configure_logging(json_output=False, level="INFO")
        self.assertGreater(len(root.filters), initial_filter_count - 1)
        has_cf = any(isinstance(f, CorrelationFilter) for f in root.filters)
        self.assertTrue(has_cf)


# ── Telemetry ────────────────────────────────────────────────────────────


class TestTelemetry(unittest.TestCase):
    def setUp(self):
        self.t = Telemetry()

    def test_counter_increment(self):
        self.t.counter("req")
        self.t.counter("req")
        self.t.counter("req", 3)
        snap = self.t.snapshot()
        self.assertEqual(snap["counters"]["req"], 5)

    def test_gauge_set(self):
        self.t.gauge("cpu", 0.75)
        self.t.gauge("cpu", 0.80)
        snap = self.t.snapshot()
        self.assertEqual(snap["gauges"]["cpu"], 0.80)

    def test_timer_context_manager(self):
        with self.t.timer("op"):
            time.sleep(0.01)
        snap = self.t.snapshot()
        self.assertIn("op", snap["timers"])
        stats = snap["timers"]["op"]
        self.assertEqual(stats["count"], 1)
        self.assertGreater(stats["mean"], 0)

    def test_timer_multiple_observations(self):
        for _ in range(10):
            with self.t.timer("fast"):
                pass
        stats = self.t.perf_stats("fast")
        self.assertEqual(stats["count"], 10)
        self.assertIn("p50", stats)
        self.assertIn("p95", stats)
        self.assertIn("p99", stats)

    def test_perf_stats_empty(self):
        self.assertEqual(self.t.perf_stats("nonexistent"), {})

    def test_all_perf_stats(self):
        with self.t.timer("a"):
            pass
        with self.t.timer("b"):
            pass
        result = self.t.all_perf_stats()
        self.assertIn("a", result)
        self.assertIn("b", result)

    def test_timer_maxlen_bounded(self):
        t = Telemetry(timer_maxlen=5)
        for _ in range(20):
            with t.timer("bounded"):
                pass
        stats = t.perf_stats("bounded")
        self.assertEqual(stats["count"], 5)

    def test_thread_safety(self):
        errors = []

        def worker():
            try:
                for _ in range(100):
                    self.t.counter("threaded")
                    self.t.gauge("g", 1.0)
                    with self.t.timer("t"):
                        pass
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(errors, [])
        snap = self.t.snapshot()
        self.assertEqual(snap["counters"]["threaded"], 400)

    def test_snapshot_returns_copies(self):
        self.t.counter("x")
        snap1 = self.t.snapshot()
        self.t.counter("x")
        snap2 = self.t.snapshot()
        self.assertEqual(snap1["counters"]["x"], 1)
        self.assertEqual(snap2["counters"]["x"], 2)


class TestTelemetrySingleton(unittest.TestCase):
    def test_module_level_singleton_exists(self):
        self.assertIsInstance(telemetry, Telemetry)


# ── Crash Diagnostics ───────────────────────────────────────────────────


class TestDiagnosticCapture(unittest.TestCase):
    def setUp(self):
        self.dc = DiagnosticCapture()

    def test_capture_returns_bundle(self):
        try:
            raise RuntimeError("test error")
        except RuntimeError as exc:
            bundle = self.dc.capture(exc, {"key": "val"})
        self.assertEqual(bundle["exception_type"], "RuntimeError")
        self.assertEqual(bundle["exception_message"], "test error")
        self.assertEqual(bundle["context"], {"key": "val"})
        self.assertIn("traceback", bundle)
        self.assertIn("timestamp", bundle)
        self.assertIn("thread", bundle)
        self.assertIn("correlation_id", bundle)

    def test_get_recent_newest_first(self):
        for i in range(5):
            self.dc.capture(ValueError(f"err{i}"))
        recent = self.dc.get_recent(3)
        self.assertEqual(len(recent), 3)
        self.assertIn("err4", recent[0]["exception_message"])
        self.assertIn("err3", recent[1]["exception_message"])

    def test_maxlen_bounded(self):
        dc = DiagnosticCapture(maxlen=3)
        for i in range(10):
            dc.capture(ValueError(f"e{i}"))
        recent = dc.get_recent(100)
        self.assertEqual(len(recent), 3)

    def test_capture_without_context(self):
        bundle = self.dc.capture(TypeError("no ctx"))
        self.assertEqual(bundle["context"], {})

    def test_install_hook(self):
        dc = DiagnosticCapture()
        original = sys.excepthook
        dc.install_hook()
        self.assertNotEqual(sys.excepthook, original)
        sys.excepthook = original


class TestDiagnosticsSingleton(unittest.TestCase):
    def test_module_level_singleton(self):
        self.assertIsInstance(diagnostics, DiagnosticCapture)


# ── Health Registry ──────────────────────────────────────────────────────


class TestHealthRegistry(unittest.TestCase):
    def setUp(self):
        self.hr = HealthRegistry()

    def test_register_and_check(self):
        self.hr.register("svc_a", lambda: {"status": "healthy", "detail": "ok"})
        result = self.hr.check_all()
        self.assertEqual(result["status"], "healthy")
        self.assertIn("svc_a", result["services"])
        self.assertEqual(result["services"]["svc_a"]["status"], "healthy")
        self.assertIn("latency_ms", result["services"]["svc_a"])

    def test_degraded_propagation(self):
        self.hr.register("good", lambda: {"status": "healthy"})
        self.hr.register("bad", lambda: {"status": "degraded"})
        result = self.hr.check_all()
        self.assertEqual(result["status"], "degraded")

    def test_exception_becomes_unavailable(self):
        self.hr.register("broken", lambda: (_ for _ in ()).throw(RuntimeError("fail")))
        def raise_fn():
            raise RuntimeError("broken check")
        self.hr.register("broken", raise_fn)
        result = self.hr.check_all()
        self.assertEqual(result["services"]["broken"]["status"], "unavailable")
        self.assertIn("error", result["services"]["broken"])
        self.assertEqual(result["status"], "degraded")

    def test_empty_registry(self):
        result = self.hr.check_all()
        self.assertEqual(result["status"], "healthy")
        self.assertEqual(result["services"], {})
        self.assertIn("checked_at", result)

    def test_non_dict_check_result(self):
        self.hr.register("simple", lambda: "ok")
        result = self.hr.check_all()
        self.assertEqual(result["services"]["simple"]["status"], "healthy")

    def test_latency_measured(self):
        def slow_check():
            time.sleep(0.02)
            return {"status": "healthy"}
        self.hr.register("slow", slow_check)
        result = self.hr.check_all()
        self.assertGreaterEqual(result["services"]["slow"]["latency_ms"], 10)


class TestHealthSingleton(unittest.TestCase):
    def test_module_level_singleton(self):
        self.assertIsInstance(health, HealthRegistry)


# ── Resource Monitor ─────────────────────────────────────────────────────


class TestResourceMonitor(unittest.TestCase):
    def setUp(self):
        self.rm = ResourceMonitor()

    def test_snapshot_keys(self):
        snap = self.rm.snapshot()
        self.assertIn("memory", snap)
        self.assertIn("cpu", snap)
        self.assertIn("threads", snap)
        self.assertIn("gc", snap)
        self.assertIn("open_fds", snap)
        self.assertIn("pid", snap)

    def test_memory_has_rss(self):
        snap = self.rm.snapshot()
        self.assertIn("rss_mb", snap["memory"])
        self.assertIn("source", snap["memory"])

    def test_cpu_has_loadavg(self):
        snap = self.rm.snapshot()
        self.assertIn("load_1m", snap["cpu"])

    def test_gc_is_list(self):
        snap = self.rm.snapshot()
        self.assertIsInstance(snap["gc"], list)

    def test_threads_positive(self):
        snap = self.rm.snapshot()
        self.assertGreater(snap["threads"], 0)

    def test_pid_matches(self):
        import os
        snap = self.rm.snapshot()
        self.assertEqual(snap["pid"], os.getpid())


class TestResourcesSingleton(unittest.TestCase):
    def test_module_level_singleton(self):
        self.assertIsInstance(resources, ResourceMonitor)


# ── Re-exports ──────────────────────────────────────────────────────────


class TestObservabilityReExports(unittest.TestCase):
    def test_all_stage3_symbols_importable(self):
        import hydra.observability as obs
        self.assertIsNotNone(obs.configure_logging)
        self.assertIsNotNone(obs.CorrelationFilter)
        self.assertIsNotNone(obs.JSONFormatter)
        self.assertIsNotNone(obs.set_correlation_id)
        self.assertIsNotNone(obs.get_correlation_id)
        self.assertIsNotNone(obs.telemetry)
        self.assertIsNotNone(obs.diagnostics)
        self.assertIsNotNone(obs.health_registry)
        self.assertIsNotNone(obs.resources)

    def test_preexisting_exports_preserved(self):
        from hydra.observability import MetricsCollector, HealthMonitor, DistributedTracer
        from hydra.observability import metrics, health, tracer
        self.assertIsInstance(metrics, MetricsCollector)
        self.assertIsInstance(health, HealthMonitor)
        self.assertIsInstance(tracer, DistributedTracer)


# ── Wiring: EventBus telemetry ──────────────────────────────────────────


class TestEventBusTelemetry(unittest.TestCase):
    def test_emit_increments_counters(self):
        t = Telemetry()
        with patch("hydra.services.event_bus._telemetry", t):
            from hydra.services.event_bus import EventBus
            bus = EventBus()
            bus.emit("test.event", {"key": "val"})
            bus.emit("test.event")
            bus.emit("other.event")
        snap = t.snapshot()
        self.assertEqual(snap["counters"]["events.total"], 3)
        self.assertEqual(snap["counters"]["events.test.event"], 2)
        self.assertEqual(snap["counters"]["events.other.event"], 1)


# ── Wiring: ServiceContainer ────────────────────────────────────────────


class TestServiceContainerWiring(unittest.TestCase):
    def test_make_times_init(self):
        t = Telemetry()
        hr = HealthRegistry()
        with patch("hydra.services.telemetry", t), \
             patch("hydra.services.health_registry", hr):
            from hydra.services import ServiceContainer
            from hydra.services.event_bus import EventBus
            container = ServiceContainer(event_bus=EventBus())
            _ = container.system
            snap = t.snapshot()
            self.assertIn("service.init.system", snap["timers"])

    def test_health_auto_registration(self):
        from hydra.services import ServiceContainer
        from hydra.services.event_bus import EventBus
        hr = HealthRegistry()
        with patch("hydra.services.health_registry", hr):
            container = ServiceContainer(event_bus=EventBus())
            _ = container.system
        result = hr.check_all()
        self.assertIn("system", result["services"])


# ── Wiring: CommandDispatcher ────────────────────────────────────────────


class TestDispatcherWiring(unittest.TestCase):
    def test_execute_sets_correlation_id(self):
        from hydra.commands.dispatcher import CommandDispatcher, CommandContext
        from hydra.commands.registry import CommandRegistry
        from hydra.services.event_bus import EventBus

        reg = CommandRegistry()
        ctx = CommandContext(None, EventBus())
        disp = CommandDispatcher(reg, ctx)

        set_correlation_id("")
        disp.execute("/nonexistent_cmd_xyz")
        cid = get_correlation_id()
        self.assertTrue(len(cid) > 0)

    def test_execute_captures_diagnostics_on_error(self):
        from hydra.commands.dispatcher import CommandDispatcher, CommandContext
        from hydra.commands.registry import CommandRegistry, Command
        from hydra.services.event_bus import EventBus

        def bad_handler(args, kwargs, ctx):
            raise RuntimeError("handler boom")

        reg = CommandRegistry()
        reg.register(Command(name="boom", description="test", handler=bad_handler))
        ctx = CommandContext(None, EventBus())
        disp = CommandDispatcher(reg, ctx)

        dc = DiagnosticCapture()
        with patch("hydra.commands.dispatcher.diagnostics", dc):
            disp.execute("/boom")

        recent = dc.get_recent(1)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["exception_type"], "RuntimeError")
        self.assertEqual(recent[0]["context"], {"command": "boom"})


# ── Wiring: RuntimeMonitor snapshot extension ────────────────────────────


class TestMonitorSnapshotExtension(unittest.TestCase):
    def test_snapshot_has_observability_keys(self):
        from hydra.services.monitor import RuntimeMonitor
        from hydra.services.event_bus import EventBus

        monitor = RuntimeMonitor(EventBus())
        snap = monitor.get_snapshot()

        self.assertIn("telemetry", snap)
        self.assertIn("health", snap)
        self.assertIn("resources", snap)
        self.assertIn("diagnostics", snap)

        self.assertIn("counters", snap["telemetry"])
        self.assertIn("status", snap["health"])
        self.assertIn("memory", snap["resources"])
        self.assertIsInstance(snap["diagnostics"], list)

    def test_original_keys_preserved(self):
        from hydra.services.monitor import RuntimeMonitor
        from hydra.services.event_bus import EventBus

        monitor = RuntimeMonitor(EventBus())
        snap = monitor.get_snapshot()

        self.assertIn("memory", snap)
        self.assertIn("cpu", snap)
        self.assertIn("uptime_seconds", snap)
        self.assertIn("workers", snap)
        self.assertIn("tasks", snap)
        self.assertIn("mcp_connections", snap)
        self.assertIn("events", snap)
        self.assertIn("pid", snap)


# ── Performance constraints ──────────────────────────────────────────────


class TestPerformanceConstraints(unittest.TestCase):
    def test_cold_import_under_200ms(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, "-c",
             "import time; t0=time.perf_counter(); "
             "from hydra.observability.logging import configure_logging; "
             "from hydra.observability.telemetry import telemetry; "
             "from hydra.observability.diagnostics import diagnostics; "
             "from hydra.observability.health import health; "
             "from hydra.observability.resources import resources; "
             "print(f'{(time.perf_counter()-t0)*1000:.1f}')"],
            capture_output=True, text=True, timeout=10,
        )
        ms = float(result.stdout.strip())
        self.assertLess(ms, 200, f"Cold import took {ms:.1f}ms (target <200ms)")

    def test_no_daemon_threads(self):
        before = {t.name for t in threading.enumerate() if t.daemon}
        Telemetry()
        DiagnosticCapture()
        HealthRegistry()
        ResourceMonitor()
        after = {t.name for t in threading.enumerate() if t.daemon}
        new_daemons = after - before
        self.assertEqual(new_daemons, set(), f"New daemon threads: {new_daemons}")

    def test_telemetry_operations_fast(self):
        t = Telemetry()
        t0 = time.perf_counter()
        for _ in range(10000):
            t.counter("perf_test")
        elapsed = (time.perf_counter() - t0) * 1000
        self.assertLess(elapsed, 500, f"10k counters took {elapsed:.1f}ms")

    def test_health_check_fast_empty(self):
        hr = HealthRegistry()
        t0 = time.perf_counter()
        for _ in range(1000):
            hr.check_all()
        elapsed = (time.perf_counter() - t0) * 1000
        self.assertLess(elapsed, 500, f"1k empty health checks took {elapsed:.1f}ms")


if __name__ == "__main__":
    unittest.main()
