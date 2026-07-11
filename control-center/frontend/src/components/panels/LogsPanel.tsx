"use client";

import { ScrollText } from "lucide-react";

export default function LogsPanel() {
  return (
    <div className="space-y-4">
      <div className="p-3 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 mb-2">
          <ScrollText className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
          <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Log Viewer</span>
        </div>
        <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
          Real-time log streaming from HYDRA subsystems, MCP server, and runtime services. Structured log aggregation with filtering.
        </div>
      </div>
      <div className="text-xs text-center py-4" style={{ color: "var(--text-muted)" }}>
        Log streaming will be connected in Phase 3 via WebSocket. Use the chat for real-time output during operations.
      </div>
    </div>
  );
}
