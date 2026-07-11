"use client";

import { useEffect, useState } from "react";
import { Workflow, RefreshCw } from "lucide-react";

export default function WorkflowsPanel() {
  const [caps, setCaps] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API}/architecture/capabilities`);
        if (res.ok) {
          const data = await res.json();
          setCaps(data.capabilities || []);
        }
      } catch {}
      setLoading(false);
    })();
  }, []);

  return (
    <div className="space-y-4">
      <div className="p-3 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 mb-2">
          <Workflow className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
          <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Workflow Engine</span>
        </div>
        <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
          Orchestrate multi-step security assessments: recon → scan → validate → report. Workflows are created and managed through chat.
        </div>
      </div>

      {caps.length > 0 && (
        <div>
          <h3 className="text-[11px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>Available Capabilities</h3>
          {caps.slice(0, 15).map((c: any) => (
            <div key={c.name} className="flex items-center justify-between text-xs py-1 border-b" style={{ borderColor: "var(--border)" }}>
              <span className="font-mono" style={{ color: "var(--text-primary)" }}>{c.name}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "var(--bg-hover)", color: "var(--accent-cyan)" }}>{c.type}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
