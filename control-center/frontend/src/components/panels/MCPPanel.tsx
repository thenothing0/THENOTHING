"use client";

import { useEffect, useState } from "react";
import { Server, Plug, RefreshCw } from "lucide-react";

interface MCPServer {
  name: string;
  command: string;
  args: string[];
  status: string;
}

export default function MCPPanel() {
  const [servers, setServers] = useState<MCPServer[]>([]);
  const [toolCount, setToolCount] = useState(0);
  const [loading, setLoading] = useState(true);

  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  const fetch_ = async () => {
    setLoading(true);
    try {
      const [srvRes, toolRes] = await Promise.all([
        fetch(`${API}/mcp/servers`),
        fetch(`${API}/mcp/tools/count`),
      ]);
      if (srvRes.ok) setServers(await srvRes.json());
      if (toolRes.ok) {
        const data = await toolRes.json();
        setToolCount(data.count);
      }
    } catch { /* */ }
    setLoading(false);
  };

  useEffect(() => { fetch_(); }, []);

  return (
    <div className="space-y-4">
      <button
        onClick={fetch_}
        className="flex items-center gap-1.5 text-xs hover:opacity-80"
        style={{ color: "var(--accent-cyan)" }}
      >
        <RefreshCw className="w-3 h-3" /> Refresh
      </button>

      {/* Summary */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1.5 text-xs" style={{ color: "var(--text-secondary)" }}>
          <Server className="w-3.5 h-3.5" style={{ color: "var(--accent-cyan)" }} />
          {servers.length} server{servers.length !== 1 ? "s" : ""}
        </div>
        <div className="flex items-center gap-1.5 text-xs" style={{ color: "var(--text-secondary)" }}>
          <Plug className="w-3.5 h-3.5" style={{ color: "var(--accent-purple)" }} />
          {toolCount} tools
        </div>
      </div>

      {/* Server list */}
      {loading ? (
        <div className="text-xs" style={{ color: "var(--text-muted)" }}>Loading...</div>
      ) : (
        servers.map((s) => (
          <div
            key={s.name}
            className="p-3 rounded-lg"
            style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
                {s.name}
              </span>
              <span
                className="text-[10px] px-1.5 py-0.5 rounded"
                style={{
                  background: "var(--bg-hover)",
                  color: s.status === "configured" ? "var(--accent-green)" : "var(--text-muted)",
                }}
              >
                {s.status}
              </span>
            </div>
            <div className="text-[11px] font-mono truncate" style={{ color: "var(--text-muted)" }}>
              {s.command} {s.args.join(" ")}
            </div>
          </div>
        ))
      )}
    </div>
  );
}
