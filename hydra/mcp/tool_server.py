"""
╔══════════════════════════════════════════════════════════════╗
║  MCP Tool Server — Real Tool Execution via Subprocess       ║
║  The ONLY interface for running security tools              ║
╚══════════════════════════════════════════════════════════════╝

All tools are REAL system tools executed via subprocess.
No mock outputs. No fake results.
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional
from pathlib import Path

from hydra.config import get_config, WORDLISTS_DIR

logger = logging.getLogger("hydra.mcp.server")


# ──────────────────────────────────────────────
#  Tool Registry — Maps logical names to commands
# ──────────────────────────────────────────────

TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {
    "subfinder": {
        "binary": "subfinder",
        "install": {"go": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
        "build_cmd": lambda params: ["subfinder", "-d", params["target"], "-silent"],
        "description": "Fast passive subdomain enumeration",
    },
    "amass": {
        "binary": "amass",
        "install": {"go": "go install -v github.com/owasp-amass/amass/v4/...@master"},
        "build_cmd": lambda params: [
            "amass", "enum", "-passive", "-d", params["target"],
        ] if params.get("mode") == "passive" else [
            "amass", "enum", "-d", params["target"],
        ],
        "description": "In-depth DNS enumeration and network mapping",
    },
    "httpx": {
        "binary": "httpx",
        "install": {"go": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"},
        "build_cmd": lambda params: ["httpx", "-silent", "-u", params.get("target", "")],
        "stdin_mode": True,
        "description": "Fast HTTP probing",
    },
    "nuclei": {
        "binary": "nuclei",
        "install": {"go": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
        "build_cmd": lambda params: [
            "nuclei", "-u", params["target"], "-jsonl", "-silent",
            "-severity", params.get("severity", "medium,high,critical"),
        ],
        "description": "Template-based vulnerability scanner",
    },
    "ffuf": {
        "binary": "ffuf",
        "install": {"go": "go install github.com/ffuf/ffuf/v2@latest"},
        "build_cmd": lambda params: [
            "ffuf", "-u", params["target"] + "/FUZZ",
            "-w", params.get("wordlist", str(WORDLISTS_DIR / "common.txt")),
            "-mc", params.get("match_codes", "200,301,302,403"),
            "-s",
        ],
        "description": "Fast web fuzzer",
    },
    "katana": {
        "binary": "katana",
        "install": {"go": "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
        "build_cmd": lambda params: [
            "katana", "-u", params["target"], "-silent", "-d", "3",
        ],
        "description": "Web crawling framework",
    },
    "gau": {
        "binary": "gau",
        "install": {"go": "go install github.com/lc/gau/v2/cmd/gau@latest"},
        "build_cmd": lambda params: ["gau", params["target"]],
        "description": "Get All URLs from various sources",
    },
    "whatweb": {
        "binary": "whatweb",
        "install": {"apt": "apt-get install -y whatweb", "brew": "brew install whatweb"},
        "build_cmd": lambda params: ["whatweb", params["target"], "--color=never"],
        "description": "Web technology fingerprinting",
    },
    "wafw00f": {
        "binary": "wafw00f",
        "install": {"pip": "pip install wafw00f"},
        "build_cmd": lambda params: ["wafw00f", params["target"]],
        "description": "WAF detection tool",
    },
    "nmap": {
        "binary": "nmap",
        "install": {"apt": "apt-get install -y nmap", "brew": "brew install nmap"},
        "build_cmd": lambda params: [
            "nmap", "-sV", "--top-ports", params.get("ports", "1000"),
            params["target"],
        ],
        "description": "Network scanner",
    },
    "dirsearch": {
        "binary": "dirsearch",
        "install": {"pip": "pip install dirsearch"},
        "build_cmd": lambda params: [
            "dirsearch", "-u", params["target"], "--format=json", "-q",
        ],
        "description": "Directory/file brute-forcer",
    },
}

# Logical tool name → physical tool mapping
TOOL_ALIASES = {
    "subdomain_enum": ["subfinder", "amass"],
    "http_probe": ["httpx"],
    "nuclei_scan": ["nuclei"],
    "fuzz_endpoint": ["ffuf"],
    "endpoint_discovery": ["katana"],
    "url_gather": ["gau"],
    "tech_detect": ["whatweb"],
    "waf_detect": ["wafw00f"],
    "port_scan": ["nmap"],
    "dir_brute": ["dirsearch"],
}


class MCPToolServer:
    """
    MCP-compliant tool execution server.
    
    All tools are executed as real subprocesses.
    No mocking, no faking, no simulation.
    """
    
    def __init__(self):
        self.config = get_config()
        self._available_tools: Dict[str, bool] = {}
        self._execution_stats: Dict[str, Dict] = {}
        self._scope_engine = None
        self._artifact_store = None

    def set_scope_engine(self, scope_engine):
        """Attach scope policy engine — blocks out-of-scope executions."""
        self._scope_engine = scope_engine
        logger.info("🔒 Scope enforcement attached to MCP tool server")

    def set_artifact_store(self, artifact_store):
        """Attach artifact store — auto-saves all tool outputs."""
        self._artifact_store = artifact_store
    
    async def initialize(self):
        """Detect available tools on the system."""
        logger.info("🔧 MCP Tool Server initializing — detecting tools...")
        
        for name, tool_def in TOOL_REGISTRY.items():
            binary = tool_def["binary"]
            path = shutil.which(binary)
            self._available_tools[name] = path is not None
            status = f"✅ {binary}" if path else f"❌ {binary} (not found)"
            logger.info(f"  {status}")
        
        available = sum(1 for v in self._available_tools.values() if v)
        total = len(self._available_tools)
        logger.info(f"🔧 {available}/{total} tools available")
    
    def get_available_tools(self) -> Dict[str, bool]:
        return dict(self._available_tools)
    
    def get_missing_tools(self) -> List[str]:
        return [name for name, avail in self._available_tools.items() if not avail]
    
    async def execute_tool(
        self,
        tool_name: str,
        params: Dict[str, Any],
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute a tool by logical name.
        
        Args:
            tool_name: Logical tool name (e.g., "subdomain_enum")
            params: Tool parameters (must include "target")
            timeout: Max execution time in seconds
            
        Returns:
            Dict with keys: success, output, stderr, elapsed, tool_used
        """
        timeout = timeout or self.config.mcp.tool_timeout
        
        # ── SCOPE ENFORCEMENT GATE ─────────────────
        target = params.get("target", "")
        if self._scope_engine and self._scope_engine.is_loaded and target:
            scope_check = self._scope_engine.validate_tool_execution(tool_name, target)
            if not scope_check.allowed:
                logger.warning(f"🚫 BLOCKED by scope: {tool_name} → {target}: {scope_check.reason}")
                return {"success": False, "error": f"Scope violation: {scope_check.reason}",
                        "output": "", "tool_used": tool_name, "blocked_by_scope": True,
                        "policy_violations": scope_check.policy_violations}
        
        # Resolve logical name to physical tool
        physical_tool = params.pop("tool", None)
        if not physical_tool:
            aliases = TOOL_ALIASES.get(tool_name, [tool_name])
            physical_tool = None
            for alias in aliases:
                if self._available_tools.get(alias):
                    physical_tool = alias
                    break
            if not physical_tool:
                physical_tool = aliases[0] if aliases else tool_name
        
        tool_def = TOOL_REGISTRY.get(physical_tool)
        if not tool_def:
            return {"success": False, "error": f"Unknown tool: {physical_tool}",
                    "output": "", "tool_used": physical_tool}
        
        # Check availability
        if not self._available_tools.get(physical_tool):
            return {"success": False,
                    "error": f"Tool not installed: {physical_tool}. Run setup.sh to install.",
                    "output": "", "tool_used": physical_tool}
        
        # Build command
        try:
            cmd = tool_def["build_cmd"](params)
        except Exception as e:
            return {"success": False, "error": f"Failed to build command: {e}",
                    "output": "", "tool_used": physical_tool}
        
        # Execute via subprocess
        logger.info(f"▶️  Executing: {' '.join(cmd)}")
        start = time.time()
        
        try:
            stdin_data = None
            if tool_def.get("stdin_mode") and "targets" in params:
                stdin_data = "\n".join(params["targets"])
                cmd = [tool_def["binary"], "-silent"]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_data.encode() if stdin_data else None),
                timeout=timeout,
            )
            
            elapsed = time.time() - start
            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            
            success = proc.returncode == 0
            
            # Track stats
            if physical_tool not in self._execution_stats:
                self._execution_stats[physical_tool] = {
                    "total": 0, "success": 0, "failed": 0, "total_time": 0
                }
            stats = self._execution_stats[physical_tool]
            stats["total"] += 1
            stats["success" if success else "failed"] += 1
            stats["total_time"] += elapsed
            
            logger.info(
                f"{'✅' if success else '⚠️'} {physical_tool} completed "
                f"in {elapsed:.1f}s (rc={proc.returncode})"
            )
            
            result = {
                "success": success,
                "output": stdout_str,
                "stderr": stderr_str,
                "return_code": proc.returncode,
                "elapsed": round(elapsed, 2),
                "tool_used": physical_tool,
            }
            
            # ── AUTO-SAVE ARTIFACTS ────────────────
            if self._artifact_store and target:
                try:
                    self._artifact_store.save_raw_output(
                        target, "scans", physical_tool, stdout_str)
                    if stderr_str.strip():
                        self._artifact_store.save_raw_output(
                            target, "logs", f"{physical_tool}_stderr", stderr_str)
                except Exception:
                    pass  # Never fail a scan because of artifact saving
            
            return result
            
        except asyncio.TimeoutError:
            elapsed = time.time() - start
            logger.warning(f"⏰ {physical_tool} timed out after {elapsed:.1f}s")
            return {"success": False, "error": f"Timeout after {timeout}s",
                    "output": "", "tool_used": physical_tool}
        except FileNotFoundError:
            return {"success": False,
                    "error": f"Binary not found: {tool_def['binary']}",
                    "output": "", "tool_used": physical_tool}
        except Exception as e:
            return {"success": False, "error": str(e),
                    "output": "", "tool_used": physical_tool}
    
    def get_stats(self) -> Dict[str, Any]:
        return dict(self._execution_stats)
