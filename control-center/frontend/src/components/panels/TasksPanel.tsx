"use client";

import { CheckSquare } from "lucide-react";

export default function TasksPanel() {
  return (
    <div className="space-y-4">
      <div className="p-3 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 mb-2">
          <CheckSquare className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
          <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Task Manager</span>
        </div>
        <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
          Engineering tasks are tracked in the conversation. Each /harness activation detects the active task from git state.
        </div>
      </div>
      <div className="text-xs text-center py-4" style={{ color: "var(--text-muted)" }}>
        Use <span className="font-mono" style={{ color: "var(--accent-cyan)" }}>/harness</span> to detect your current task and build engineering context.
      </div>
    </div>
  );
}
