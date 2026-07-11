"use client";

import { useEffect, useState } from "react";
import { BrainCircuit, RefreshCw } from "lucide-react";

interface RepoFull {
  classes: { name: string; file: string; method_count: number }[];
  functions: { name: string; file: string; is_async: boolean }[];
  modules: { name: string; file_count: number }[];
  apis: { method: string; endpoint: string; file: string }[];
  stats: { class_count: number; function_count: number; module_count: number; api_count: number };
}

type Tab = "classes" | "functions" | "apis" | "modules";

export default function RepoMemoryPanel() {
  const [data, setData] = useState<RepoFull | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>("classes");
  const [filter, setFilter] = useState("");
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  const fetch_ = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/repo/full`);
      if (res.ok) setData(await res.json());
    } catch {}
    setLoading(false);
  };

  useEffect(() => { fetch_(); }, []);

  if (loading) return <div className="text-xs" style={{ color: "var(--text-muted)" }}>Indexing repository memory...</div>;
  if (!data) return <div className="text-xs" style={{ color: "var(--accent-red)" }}>Backend offline</div>;

  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: "classes", label: "Classes", count: data.stats.class_count },
    { key: "functions", label: "Functions", count: data.stats.function_count },
    { key: "apis", label: "APIs", count: data.stats.api_count },
    { key: "modules", label: "Modules", count: data.stats.module_count },
  ];

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter..."
          className="flex-1 px-2 py-1.5 rounded text-xs bg-transparent outline-none"
          style={{ border: "1px solid var(--border)", color: "var(--text-primary)" }}
        />
        <button onClick={fetch_} className="p-1.5 rounded" style={{ color: "var(--accent-cyan)" }}>
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className="px-2 py-1 rounded text-[11px]"
            style={{
              background: tab === t.key ? "var(--accent-cyan)" : "var(--bg-hover)",
              color: tab === t.key ? "#000" : "var(--text-secondary)",
            }}
          >
            {t.label} <span className="opacity-60">{t.count}</span>
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="space-y-1 max-h-[500px] overflow-y-auto">
        {tab === "classes" && data.classes
          .filter((c) => !filter || c.name.toLowerCase().includes(filter.toLowerCase()))
          .slice(0, 50)
          .map((c, i) => (
            <div key={i} className="flex items-center justify-between text-xs py-1 border-b" style={{ borderColor: "var(--border)" }}>
              <div>
                <span className="font-mono" style={{ color: "var(--accent-cyan)" }}>{c.name}</span>
                <span className="ml-2 text-[10px]" style={{ color: "var(--text-muted)" }}>{c.file}</span>
              </div>
              <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>{c.method_count}m</span>
            </div>
          ))}

        {tab === "functions" && data.functions
          .filter((f) => !filter || f.name.toLowerCase().includes(filter.toLowerCase()))
          .slice(0, 50)
          .map((f, i) => (
            <div key={i} className="flex items-center justify-between text-xs py-1 border-b" style={{ borderColor: "var(--border)" }}>
              <div>
                <span className="font-mono" style={{ color: f.is_async ? "var(--accent-purple)" : "var(--accent-cyan)" }}>
                  {f.is_async ? "async " : ""}{f.name}
                </span>
                <span className="ml-2 text-[10px]" style={{ color: "var(--text-muted)" }}>{f.file}</span>
              </div>
            </div>
          ))}

        {tab === "apis" && data.apis
          .filter((a) => !filter || a.endpoint.toLowerCase().includes(filter.toLowerCase()))
          .slice(0, 50)
          .map((a, i) => (
            <div key={i} className="flex items-center gap-2 text-xs py-1 border-b" style={{ borderColor: "var(--border)" }}>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-bold" style={{
                background: "var(--bg-hover)",
                color: a.method === "GET" ? "var(--accent-green)" : a.method === "POST" ? "var(--accent-cyan)" : a.method === "DELETE" ? "var(--accent-red)" : "var(--accent-amber)",
              }}>{a.method}</span>
              <span className="font-mono" style={{ color: "var(--text-primary)" }}>{a.endpoint}</span>
              <span className="text-[10px] ml-auto" style={{ color: "var(--text-muted)" }}>{a.file}</span>
            </div>
          ))}

        {tab === "modules" && data.modules
          .filter((m) => !filter || m.name.toLowerCase().includes(filter.toLowerCase()))
          .slice(0, 50)
          .map((m, i) => (
            <div key={i} className="flex items-center justify-between text-xs py-1 border-b" style={{ borderColor: "var(--border)" }}>
              <span className="font-mono" style={{ color: "var(--text-primary)" }}>{m.name}</span>
              <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>{m.file_count} files</span>
            </div>
          ))}
      </div>
    </div>
  );
}
