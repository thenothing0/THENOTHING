"use client";

import { FileText } from "lucide-react";

export default function ReportsPanel() {
  return (
    <div className="space-y-4">
      <div className="p-3 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 mb-2">
          <FileText className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
          <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Report Generator</span>
        </div>
        <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
          Generate structured bug bounty reports from confirmed findings. Supports HackerOne, Bugcrowd, and custom templates.
        </div>
      </div>
      <div className="text-xs text-center py-4" style={{ color: "var(--text-muted)" }}>
        Use <span className="font-mono" style={{ color: "var(--accent-cyan)" }}>/report</span> in chat to generate a report from findings.
      </div>
    </div>
  );
}
