"use client";

import { useEffect, useState } from "react";

interface StatusInfo {
  branch: string;
  mcp_tools: number;
  runtime: string;
}

export default function BottomBar() {
  const [status, setStatus] = useState<StatusInfo>({
    branch: "...",
    mcp_tools: 0,
    runtime: "connecting",
  });

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api"}/dashboard/stats`,
        );
        if (res.ok) {
          const data = await res.json();
          setStatus({
            branch: data.branch || "unknown",
            mcp_tools: data.mcp_tool_count || 0,
            runtime: data.runtime_status || "ready",
          });
        }
      } catch {
        setStatus((s) => ({ ...s, runtime: "offline" }));
      }
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const runtimeColor =
    status.runtime === "ready"
      ? "var(--accent-green)"
      : status.runtime === "offline"
        ? "var(--accent-red)"
        : "var(--accent-amber)";

  return (
    <div
      className="flex items-center justify-between px-3 h-6 shrink-0 border-t text-[11px] select-none"
      style={{
        borderColor: "var(--border)",
        background: "var(--bg-primary)",
        color: "var(--text-muted)",
      }}
    >
      <div className="flex items-center gap-3">
        <span>{status.branch}</span>
        <span style={{ color: "var(--border)" }}>│</span>
        <span>mcp:{status.mcp_tools}</span>
        <span style={{ color: "var(--border)" }}>│</span>
        <span style={{ color: runtimeColor }}>●</span>
        <span>{status.runtime}</span>
      </div>
      <div className="flex items-center gap-3">
        <span>hydra v1.0</span>
        <span style={{ color: "var(--border)" }}>│</span>
        <span>ctrl+shift+p</span>
      </div>
    </div>
  );
}
