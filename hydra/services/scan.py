"""Scan service — wraps RuntimeOrchestrator and MCP tool execution.

Emits events throughout the lifecycle:
  tool.started  → tool.output (chunks) → tool.completed | tool.failed
"""

import time

from hydra.services.base import BaseService


class ScanService(BaseService):

    def execute_recon(self, target, depth=3):
        tool_id = f"recon-{int(time.time())}"
        self._emit("tool.started", {"tool": "recon", "target": target, "tool_id": tool_id})
        self._emit("tool.output", {"tool": "recon", "chunk": f"Starting recon on {target} (depth={depth})..."})
        try:
            from hydra.runtime_orchestrator import RuntimeOrchestrator
            orch = RuntimeOrchestrator()
            result = orch.run_recon(target, depth=depth)
            self._emit("tool.output", {"tool": "recon", "chunk": f"Recon complete. Found {len(result) if isinstance(result, (list, dict)) else '?'} items."})
            self._emit("tool.completed", {"tool": "recon", "target": target, "result": result, "tool_id": tool_id})
            return result
        except ImportError:
            self._emit("tool.output", {"tool": "recon", "chunk": "RuntimeOrchestrator not available — using MCP fallback"})
            result = self._mcp_recon(target, depth)
            self._emit("tool.completed", {"tool": "recon", "target": target, "result": result, "tool_id": tool_id})
            return result
        except Exception as e:
            self._emit("tool.failed", {"tool": "recon", "target": target, "error": str(e), "tool_id": tool_id})
            return {"error": str(e)}

    def execute_scan(self, target, vuln_class, **kw):
        tool_id = f"scan-{int(time.time())}"
        self._emit("tool.started", {"tool": "scan", "target": target, "vuln_class": vuln_class, "tool_id": tool_id})
        self._emit("tool.output", {"tool": "scan", "chunk": f"Scanning {target} for {vuln_class}..."})
        try:
            from hydra.runtime_orchestrator import RuntimeOrchestrator
            orch = RuntimeOrchestrator()
            result = orch.run_scan(target, vuln_class=vuln_class, **kw)
            confirmed = len(result.get("confirmed_findings", [])) if isinstance(result, dict) else 0
            suspected = len(result.get("suspected", [])) if isinstance(result, dict) else 0
            self._emit("tool.output", {"tool": "scan", "chunk": f"Scan complete. {confirmed} confirmed, {suspected} suspected."})
            self._emit("tool.completed", {"tool": "scan", "target": target, "result": result, "tool_id": tool_id})
            return result
        except ImportError:
            self._emit("tool.output", {"tool": "scan", "chunk": "RuntimeOrchestrator not available — using MCP fallback"})
            result = self._mcp_scan(target, vuln_class, **kw)
            self._emit("tool.completed", {"tool": "scan", "target": target, "result": result, "tool_id": tool_id})
            return result
        except Exception as e:
            self._emit("tool.failed", {"tool": "scan", "target": target, "error": str(e), "tool_id": tool_id})
            return {"error": str(e)}

    def execute_campaign(self, target, classes="xss,sqli,open_redirect,lfi,ssti"):
        tool_id = f"campaign-{int(time.time())}"
        class_list = [c.strip() for c in classes.split(",") if c.strip()]
        self._emit("tool.started", {"tool": "campaign", "target": target, "tool_id": tool_id})
        self._emit("tool.output", {"tool": "campaign", "chunk": f"Campaign against {target} ({len(class_list)} classes)..."})

        all_results = {"confirmed": [], "suspected": [], "errors": []}
        for i, cls in enumerate(class_list, 1):
            self._emit("tool.output", {"tool": "campaign", "chunk": f"[{i}/{len(class_list)}] Scanning {cls}..."})
            try:
                r = self.execute_scan(target, cls)
                if isinstance(r, dict):
                    all_results["confirmed"].extend(r.get("confirmed_findings", []))
                    all_results["suspected"].extend(r.get("suspected", []))
            except Exception as e:
                all_results["errors"].append({"class": cls, "error": str(e)})

        self._emit("tool.output", {
            "tool": "campaign",
            "chunk": f"Campaign done. {len(all_results['confirmed'])} confirmed, {len(all_results['suspected'])} suspected."
        })
        self._emit("tool.completed", {"tool": "campaign", "target": target, "result": all_results, "tool_id": tool_id})
        return all_results

    def list_available_tools(self):
        try:
            from hydra.tool_gateway import ToolGateway
            gw = ToolGateway()
            return gw.list_tools()
        except Exception:
            return []

    def _mcp_recon(self, target, depth):
        """Fallback: describe what MCP tools would be called."""
        return {
            "status": "mcp_fallback",
            "target": target,
            "note": "Use MCP tools: subfinder_scan, httpx_probe, whatweb_detect",
            "tools": ["subfinder_scan", "httpx_probe", "whatweb_detect", "katana_crawl"],
        }

    def _mcp_scan(self, target, vuln_class, **kw):
        """Fallback: describe what MCP tools would be called."""
        return {
            "status": "mcp_fallback",
            "target": target,
            "vuln_class": vuln_class,
            "note": f"Use MCP tools: attack_scan for {vuln_class}",
            "tools": ["attack_scan", "attack_recon_scan"],
        }
