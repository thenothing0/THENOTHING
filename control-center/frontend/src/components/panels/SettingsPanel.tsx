"use client";

import { Settings } from "lucide-react";

export default function SettingsPanel() {
  return (
    <div className="space-y-4">
      <div className="p-3 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 mb-2">
          <Settings className="w-4 h-4" style={{ color: "var(--text-secondary)" }} />
          <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Settings</span>
        </div>
        <div className="text-xs space-y-2" style={{ color: "var(--text-secondary)" }}>
          <div>
            <span style={{ color: "var(--text-muted)" }}>Backend:</span> http://localhost:8081
          </div>
          <div>
            <span style={{ color: "var(--text-muted)" }}>Frontend:</span> http://localhost:3000
          </div>
          <div>
            <span style={{ color: "var(--text-muted)" }}>MCP Transport:</span> stdio
          </div>
          <div>
            <span style={{ color: "var(--text-muted)" }}>Theme:</span> Dark (HYDRA)
          </div>
        </div>
      </div>

      <div className="text-xs" style={{ color: "var(--text-muted)" }}>
        Configuration is managed through environment variables and the backend config. Provider API keys are encrypted at rest with Fernet.
      </div>
    </div>
  );
}
