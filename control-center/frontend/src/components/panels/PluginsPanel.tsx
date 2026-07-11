"use client";

import { useEffect, useState } from "react";
import { Package, RefreshCw } from "lucide-react";

export default function PluginsPanel() {
  const [plugins, setPlugins] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  const fetch_ = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/discovery/plugins`);
      if (res.ok) setPlugins(await res.json());
    } catch {}
    setLoading(false);
  };

  useEffect(() => { fetch_(); }, []);

  return (
    <div className="space-y-4">
      <button onClick={fetch_} className="flex items-center gap-1.5 text-xs" style={{ color: "var(--accent-cyan)" }}>
        <RefreshCw className="w-3 h-3" /> Refresh
      </button>

      <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
        <Package className="w-3.5 h-3.5 inline mr-1" style={{ color: "var(--accent-cyan)" }} />
        {plugins.length} plugins discovered
      </div>

      {plugins.map((p: any) => (
        <div key={p.id} className="p-2.5 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-medium" style={{ color: "var(--text-primary)" }}>{p.name || p.id}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "var(--bg-hover)", color: "var(--accent-purple)" }}>{p.source}</span>
          </div>
          {p.path && <div className="text-[10px] font-mono truncate" style={{ color: "var(--text-muted)" }}>{p.path}</div>}
          {p.version && <div className="text-[10px]" style={{ color: "var(--text-muted)" }}>v{p.version}</div>}
        </div>
      ))}

      {plugins.length === 0 && !loading && (
        <div className="text-xs text-center py-4" style={{ color: "var(--text-muted)" }}>No plugins discovered. Plugins are loaded from hydra/plugins/ and data/plugins/.</div>
      )}
    </div>
  );
}
