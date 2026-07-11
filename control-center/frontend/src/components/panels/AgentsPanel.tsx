"use client";

import { useEffect, useState } from "react";
import { Bot, RefreshCw } from "lucide-react";

export default function AgentsPanel() {
  const [caps, setCaps] = useState<any[]>([]);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API}/architecture/capabilities`);
        if (res.ok) {
          const data = await res.json();
          setCaps((data.capabilities || []).filter((c: any) => c.type === "subsystem"));
        }
      } catch {}
    })();
  }, []);

  return (
    <div className="space-y-4">
      <div className="p-3 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 mb-2">
          <Bot className="w-4 h-4" style={{ color: "var(--accent-purple)" }} />
          <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Agent Orchestration</span>
        </div>
        <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
          HYDRA agents are specialized subsystems orchestrated through the cognitive loop. Each agent handles a domain of offensive security.
        </div>
      </div>

      {caps.length > 0 && (
        <div>
          <h3 className="text-[11px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>
            Discovered Subsystems ({caps.length})
          </h3>
          {caps.slice(0, 25).map((c: any) => (
            <div key={c.name} className="text-xs font-mono py-0.5" style={{ color: "var(--text-secondary)" }}>{c.name}</div>
          ))}
        </div>
      )}
    </div>
  );
}
