"use client";

import { useEffect, useState } from "react";
import { Database, RefreshCw } from "lucide-react";

export default function KnowledgePanel() {
  const [sources, setSources] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  const fetch_ = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/discovery/knowledge`);
      if (res.ok) setSources(await res.json());
    } catch {}
    setLoading(false);
  };

  useEffect(() => { fetch_(); }, []);

  if (loading) return <div className="text-xs" style={{ color: "var(--text-muted)" }}>Discovering knowledge sources...</div>;

  return (
    <div className="space-y-4">
      <button onClick={fetch_} className="flex items-center gap-1.5 text-xs" style={{ color: "var(--accent-cyan)" }}>
        <RefreshCw className="w-3 h-3" /> Refresh
      </button>

      <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
        <Database className="w-3.5 h-3.5 inline mr-1" style={{ color: "var(--accent-cyan)" }} />
        {sources.length} knowledge sources discovered
      </div>

      {sources.map((s: any) => (
        <div key={s.id} className="p-2.5 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>{s.name || s.id}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "var(--bg-hover)", color: "var(--accent-cyan)" }}>{s.type}</span>
          </div>
          {s.count !== undefined && <div className="text-[11px]" style={{ color: "var(--text-muted)" }}>{s.count} items</div>}
          {s.path && <div className="text-[10px] font-mono truncate" style={{ color: "var(--text-muted)" }}>{s.path}</div>}
        </div>
      ))}
    </div>
  );
}
