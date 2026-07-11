"""Engineering Copilot Service — AI-assisted security engineering (Phase 10.10)."""

from __future__ import annotations

import time
from pathlib import Path

from hydra.services.base import BaseService
from hydra.services.event_bus import EventBus

SUGGESTION_TYPES = {"next_action", "tool_recommendation", "technique", "payload", "bypass", "chain", "remediation"}
COPILOT_MODES = {"passive", "active", "autonomous"}
CONTEXT_TYPES = {"target", "finding", "workflow", "engagement", "technique"}


class CopilotService(BaseService):

    def __init__(self, event_bus: EventBus, data_dir: Path | None = None):
        super().__init__(event_bus, data_dir)
        self._mode = "passive"
        self._suggestions: list[dict] = []
        self._accepted: list[str] = []
        self._rejected: list[str] = []
        self._context: dict[str, dict] = {}

    def suggest(self, context: dict | None = None) -> dict:
        ctx = context or {}
        target = ctx.get("target", "unknown")
        vuln_class = ctx.get("vuln_class", "")
        phase = ctx.get("phase", "recon")

        suggestions = self._generate_suggestions(target, vuln_class, phase)
        for s in suggestions:
            self._suggestions.append(s)

        self._emit("copilot.suggestions_generated", {"count": len(suggestions), "target": target})
        return {
            "status": "generated",
            "count": len(suggestions),
            "suggestions": suggestions,
        }

    def accept_suggestion(self, suggestion_id: str) -> dict:
        target = None
        for s in self._suggestions:
            if s["id"] == suggestion_id:
                target = s
                break
        if not target:
            return {"status": "error", "message": f"Suggestion {suggestion_id} not found"}
        target["state"] = "accepted"
        self._accepted.append(suggestion_id)
        self._emit("copilot.suggestion_accepted", {"id": suggestion_id})
        return {"status": "accepted", "suggestion": target}

    def reject_suggestion(self, suggestion_id: str, reason: str = "") -> dict:
        target = None
        for s in self._suggestions:
            if s["id"] == suggestion_id:
                target = s
                break
        if not target:
            return {"status": "error", "message": f"Suggestion {suggestion_id} not found"}
        target["state"] = "rejected"
        target["reject_reason"] = reason
        self._rejected.append(suggestion_id)
        self._emit("copilot.suggestion_rejected", {"id": suggestion_id})
        return {"status": "rejected", "suggestion": target}

    def set_mode(self, mode: str) -> dict:
        if mode not in COPILOT_MODES:
            return {"status": "error", "message": f"Unknown mode: {mode}. Valid: {COPILOT_MODES}"}
        old = self._mode
        self._mode = mode
        self._emit("copilot.mode_changed", {"old": old, "new": mode})
        return {"status": "changed", "old_mode": old, "new_mode": mode}

    def set_context(self, context_type: str, data: dict) -> dict:
        if context_type not in CONTEXT_TYPES:
            return {"status": "error", "message": f"Unknown context type: {context_type}"}
        self._context[context_type] = {**data, "updated_at": time.time()}
        return {"status": "set", "context_type": context_type}

    def get_context(self) -> dict:
        return {"mode": self._mode, "contexts": self._context}

    def explain(self, topic: str) -> dict:
        explanations = {
            "xss": {
                "summary": "Cross-Site Scripting allows injection of client-side scripts",
                "impact": "Session hijacking, credential theft, defacement",
                "techniques": ["reflected", "stored", "dom-based", "blind"],
                "tools": ["dalfox", "gxss", "nuclei"],
            },
            "sqli": {
                "summary": "SQL Injection allows manipulation of database queries",
                "impact": "Data exfiltration, authentication bypass, RCE via stacked queries",
                "techniques": ["union", "blind-boolean", "blind-time", "error-based", "stacked"],
                "tools": ["sqlmap", "nuclei"],
            },
            "ssrf": {
                "summary": "Server-Side Request Forgery forces the server to make unintended requests",
                "impact": "Internal service access, cloud metadata theft, port scanning",
                "techniques": ["basic", "blind", "dns-rebinding", "protocol-smuggling"],
                "tools": ["nuclei", "ffuf"],
            },
            "idor": {
                "summary": "Insecure Direct Object Reference allows unauthorized resource access",
                "impact": "Data theft, privilege escalation, account takeover",
                "techniques": ["id-enumeration", "uuid-guessing", "path-traversal", "parameter-tampering"],
                "tools": ["burp", "ffuf"],
            },
        }
        info = explanations.get(topic.lower(), {
            "summary": f"No detailed explanation available for '{topic}'",
            "impact": "Varies",
            "techniques": [],
            "tools": [],
        })
        return {"status": "explained", "topic": topic, **info}

    def get_stats(self) -> dict:
        return {
            "mode": self._mode,
            "total_suggestions": len(self._suggestions),
            "accepted": len(self._accepted),
            "rejected": len(self._rejected),
            "pending": len(self._suggestions) - len(self._accepted) - len(self._rejected),
            "acceptance_rate": (
                len(self._accepted) / len(self._suggestions)
                if self._suggestions else 0.0
            ),
            "contexts_set": len(self._context),
        }

    def _generate_suggestions(self, target: str, vuln_class: str, phase: str) -> list[dict]:
        suggestions = []
        phase_suggestions = {
            "recon": [
                {"type": "next_action", "action": "Run subdomain enumeration", "tool": "subfinder", "priority": "high"},
                {"type": "next_action", "action": "Probe live hosts", "tool": "httpx", "priority": "high"},
                {"type": "technique", "action": "Check for subdomain takeover", "tool": "subzy", "priority": "medium"},
            ],
            "scan": [
                {"type": "tool_recommendation", "action": "Run nuclei templates", "tool": "nuclei", "priority": "high"},
                {"type": "next_action", "action": "Crawl for endpoints", "tool": "katana", "priority": "high"},
                {"type": "technique", "action": "Fuzz directories", "tool": "ffuf", "priority": "medium"},
            ],
            "exploit": [
                {"type": "payload", "action": "Generate context-aware payloads", "tool": "attack_plan", "priority": "high"},
                {"type": "chain", "action": "Look for exploit chains", "tool": "attack_chain_execute", "priority": "medium"},
            ],
        }

        base = phase_suggestions.get(phase, phase_suggestions["recon"])
        for i, s in enumerate(base):
            suggestions.append({
                "id": f"sug-{int(time.time() * 1000)}-{i}",
                "state": "pending",
                "target": target,
                "vuln_class": vuln_class,
                **s,
            })

        if vuln_class:
            vuln_tools = {
                "xss": {"tool": "dalfox", "action": "Run XSS-specific scanner"},
                "sqli": {"tool": "sqlmap", "action": "Run SQL injection scanner"},
                "ssrf": {"tool": "nuclei", "action": "Run SSRF templates"},
            }
            if vuln_class in vuln_tools:
                suggestions.append({
                    "id": f"sug-{int(time.time() * 1000)}-vuln",
                    "state": "pending",
                    "target": target,
                    "vuln_class": vuln_class,
                    "type": "tool_recommendation",
                    "priority": "high",
                    **vuln_tools[vuln_class],
                })

        return suggestions
