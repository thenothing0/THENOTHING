"""Regenerate the MCP tool-contract baseline. Run: python tests/mcp/_regen_baseline.py"""
import asyncio
import json
from pathlib import Path

import mcp_server


def main() -> None:
    tools = asyncio.run(mcp_server.mcp.list_tools())
    data = {
        t.name: {
            "required": sorted((t.inputSchema or {}).get("required", [])),
            "params": sorted(((t.inputSchema or {}).get("properties") or {}).keys()),
        }
        for t in tools
    }
    out = Path(__file__).with_name("tool_contract_baseline.json")
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"baseline tools: {len(data)}")


if __name__ == "__main__":
    main()
