"use client";

import { useEffect, useState } from "react";
import { Brain, RefreshCw } from "lucide-react";

export default function ThreatIntelPanel() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  const fetch_ = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/discovery/knowledge`);
      if (res.ok) {
        const sources = await res.json();
        const intel = sources.filter((s: any) => s.id === "intel" || s.id === "findings" || s.id === "chains" || s.id === "patterns");
        setData({ sources: intel, total: sources.length });
      }
    } catch {}
    setLoading(false);
  };

  useEffect(() => { fetch_(); }, []);

  if (loading) return <div className="text-xs" style={{ color: "var(--text-muted)" }}>Loading threat intelligence...</div>;

  return (
    <div className="space-y-4">
      <button onClick={fetch_} className="flex items-center gap-1.5 text-xs" style={{ color: "var(--accent-cyan)" }}>
        <RefreshCw className="w-3 h-3" /> Refresh
      </button>

      <div className="p-3 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 mb-2">
          <Brain className="w-4 h-4" style={{ color: "var(--accent-purple)" }} />
          <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Knowledge OS</span>
        </div>
        <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
          Phases A–U intelligence pipeline. Patterns, chains, findings, and intel are surfaced from the wiki knowledge graph.
        </div>
      </div>

      {data?.sources?.map((s: any) => (
        <div key={s.id} className="p-2.5 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>{s.name || s.id}</span>
            <span className="text-[10px]" style={{ color: "var(--accent-purple)" }}>{s.count} items</span>
          </div>
        </div>
      ))}

      {(!data?.sources || data.sources.length === 0) && (
        <div className="text-xs text-center py-4" style={{ color: "var(--text-muted)" }}>
          No threat intelligence data yet. Run recon and ingest reports to build the knowledge graph.
        </div>
      )}
    </div>
  );
}
