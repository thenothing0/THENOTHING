"use client";

import { Target } from "lucide-react";

export default function ImpactPanel() {
  return (
    <div className="space-y-4">
      <div className="p-3 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 mb-2">
          <Target className="w-4 h-4" style={{ color: "var(--accent-amber)" }} />
          <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Impact Analysis</span>
        </div>
        <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
          Analyzes the impact of code changes across the codebase. Shows affected modules, downstream dependencies, and risk areas.
        </div>
      </div>
      <div className="text-xs" style={{ color: "var(--text-muted)" }}>
        Impact analysis is automatically run as part of the Guard Pipeline when /harness is activated. View detailed results in the Guards panel.
      </div>
    </div>
  );
}
