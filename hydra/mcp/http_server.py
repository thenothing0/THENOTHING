"""
╔══════════════════════════════════════════════════════════════╗
║  MCP HTTP Server — JSON-RPC API for tool execution          ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
from typing import Any, Dict

from aiohttp import web

from hydra.mcp.tool_server import MCPToolServer, TOOL_REGISTRY

logger = logging.getLogger("hydra.mcp.http")


class MCPHTTPServer:
    """HTTP server exposing MCP tool execution via JSON-RPC."""
    
    def __init__(self, tool_server: MCPToolServer, host: str = "0.0.0.0", port: int = 8900):
        self.tool_server = tool_server
        self.host = host
        self.port = port
        self.app = web.Application()
        self._setup_routes()
    
    def _setup_routes(self):
        self.app.router.add_post("/execute", self.handle_execute)
        self.app.router.add_get("/tools", self.handle_list_tools)
        self.app.router.add_get("/health", self.handle_health)
        self.app.router.add_get("/stats", self.handle_stats)
    
    async def handle_execute(self, request: web.Request) -> web.Response:
        """Execute a tool via MCP."""
        try:
            body = await request.json()
            tool_name = body.get("tool")
            params = body.get("params", {})
            timeout = body.get("timeout")
            
            if not tool_name:
                return web.json_response(
                    {"error": "Missing 'tool' field"}, status=400
                )
            
            result = await self.tool_server.execute_tool(tool_name, params, timeout)
            return web.json_response(result)
            
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)
        except Exception as e:
            logger.error(f"Execute error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def handle_list_tools(self, request: web.Request) -> web.Response:
        """List all registered tools and their availability."""
        tools = {}
        available = self.tool_server.get_available_tools()
        for name, tool_def in TOOL_REGISTRY.items():
            tools[name] = {
                "description": tool_def["description"],
                "binary": tool_def["binary"],
                "available": available.get(name, False),
            }
        return web.json_response({"tools": tools})
    
    async def handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "healthy", "service": "mcp-tool-server"})
    
    async def handle_stats(self, request: web.Request) -> web.Response:
        return web.json_response(self.tool_server.get_stats())
    
    async def start(self):
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        logger.info(f"🌐 MCP HTTP Server running at http://{self.host}:{self.port}")
    
    async def start_standalone(self):
        """Start as standalone server (blocking)."""
        await self.tool_server.initialize()
        web.run_app(self.app, host=self.host, port=self.port)
