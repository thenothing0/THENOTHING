"""
Runtime Integration Layer — turns the subsystems from MCP-callable modules into
load-bearing runtime participants.

Every tool execution in the autonomous runtime flows through ONE chokepoint:

    Tool Request → ToolGateway (RBAC → HITL → Authorization) → execute
                 → Coverage update → Finding extraction → Learning → Session save

  * ToolGateway        — MANDATORY enforcement (deny stops execution; approvals
                         + denials recorded to an audit log). Not advisory.
  * extract_findings   — turn tool output into draft findings (no manual creation).
  * RuntimeOrchestrator— the post-execution pipeline that drives Findings/Coverage/
                         Learning/Session automatically.

Deterministic, stdlib + the existing stores; no mocks.
"""

from .evidence import EvidenceFinding, extract_findings, vuln_class_for_tool
from .gateway import GateDecision, ToolGateway
from .orchestrator import RuntimeContext, RuntimeOrchestrator

__all__ = [
    "ToolGateway",
    "GateDecision",
    "RuntimeOrchestrator",
    "RuntimeContext",
    "extract_findings",
    "vuln_class_for_tool",
    "EvidenceFinding",
]
