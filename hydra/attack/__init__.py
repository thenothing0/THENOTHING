"""
Hydra Attack Section — executable, authorization-gated offensive capability.

Improves the attack section across seven fronts, all built INSIDE the safety model established by the
bug-bounty authorization gate (deny-by-default, PoC-only, absolute prohibitions intact):

  1. AttackWorkflow      — guarded validate-then-exploit orchestrator (gate.require → technique →
                           payloads → chains → injectable executor → evidence). The keystone.
  2. OOBCorrelator       — out-of-band / blind detection (tokens + payloads + correlation; pluggable
                           listener — no live server stood up here).
  3. PayloadLibrary      — context-aware PoC payloads + WAF-adaptive mutation (reuses PayloadMutator).
  4. Bypass403Generator  — automated 403/WAF bypass (the methodology, made runnable).
  5. ChainTemplateEngine — classic high-value chain templates + realized-severity elevation + ATT&CK.
  6. EvidenceCollector   — reproducible PoC evidence (request/response, curl, screenshot hook).
  7. AttackQueue         — intelligence-driven attack prioritization.

Every payload is detection / proof-of-concept grade (no exfiltration / destruction / DoS). All
target-touching network I/O is confined to an injectable Executor (default `DryRunExecutor` sends
nothing) that runs only after the bug-bounty gate has authorized the target. Deterministic, offline by
default; promotion.py / confidence.py / the canonical wiki are untouched.
"""

from hydra.attack.chain_exec import ChainExecutor, redact
from hydra.attack.chain_templates import CHAIN_TEMPLATES, ChainTemplate, ChainTemplateEngine
from hydra.attack.crawl_seed import CrawlSeeder, param_signature
from hydra.attack.graphql import GraphQLTester
from hydra.attack.jwt_attacks import JWTAnalyzer
from hydra.attack.knowledge_loop import FindingPublisher
from hydra.attack.rbac import PrivilegeEscalationTester
from hydra.attack.two_signal import Confirmation, Signal, TwoSignalConfirmer
from hydra.attack.web_probes import CachePoisonProbe, CORSProbe, HostHeaderProbe, SmugglingPlan
from hydra.attack.detection import AccessControlAnalyzer, DifferentialDetector, is_waf_block
from hydra.attack.evidence import EvidenceBundle, EvidenceCollector, curl_repro
from hydra.attack.injection_points import InjectionPoint, InjectionPointFinder
from hydra.attack.oob import ListenerConfig, OOBCorrelator, OOBToken
from hydra.attack.report_builder import AttackReporter, record_outcome
from hydra.attack.payloads import (
    Payload,
    PayloadContext,
    PayloadLibrary,
    VulnClass,
    WafFeedback,
)
from hydra.attack.queue import AttackQueue
from hydra.attack.waf_bypass import Bypass403Generator, BypassAttempt
from hydra.attack.workflow import AttackResult, AttackWorkflow, DryRunExecutor

__all__ = [
    "AttackWorkflow",
    "AttackResult",
    "DryRunExecutor",
    "PayloadLibrary",
    "Payload",
    "VulnClass",
    "PayloadContext",
    "WafFeedback",
    "Bypass403Generator",
    "BypassAttempt",
    "OOBCorrelator",
    "OOBToken",
    "ListenerConfig",
    "ChainTemplateEngine",
    "ChainTemplate",
    "CHAIN_TEMPLATES",
    "EvidenceCollector",
    "EvidenceBundle",
    "curl_repro",
    "AttackQueue",
    "DifferentialDetector",
    "AccessControlAnalyzer",
    "is_waf_block",
    "InjectionPointFinder",
    "InjectionPoint",
    "ChainExecutor",
    "redact",
    "AttackReporter",
    "record_outcome",
    "CrawlSeeder",
    "param_signature",
    "TwoSignalConfirmer",
    "Signal",
    "Confirmation",
    "GraphQLTester",
    "JWTAnalyzer",
    "CORSProbe",
    "CachePoisonProbe",
    "HostHeaderProbe",
    "SmugglingPlan",
    "PrivilegeEscalationTester",
    "FindingPublisher",
]
