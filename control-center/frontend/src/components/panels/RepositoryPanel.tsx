"use client";

import { useEffect, useState } from "react";
import { FolderGit2, RefreshCw, FileCode, Package, Globe } from "lucide-react";

interface RepoSummary {
  file_count: number;
  module_count: number;
  api_count: number;
  dependency_count: number;
  architecture: { patterns: string[]; services: string[]; frameworks: string[] };
  top_modules: string[];
  dependencies: Record<string, string[]>;
}

export default function RepositoryPanel() {
  const [data, setData] = useState<RepoSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  const fetch_ = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/repo/summary`);
      if (res.ok) setData(await res.json());
    } catch {}
    setLoading(false);
  };

  useEffect(() => { fetch_(); }, []);

  if (loading) return <div className="text-xs" style={{ color: "var(--text-muted)" }}>Indexing repository...</div>;
  if (!data) return <div className="text-xs" style={{ color: "var(--accent-red)" }}>Backend offline</div>;

  return (
    <div className="space-y-4">
      <button onClick={fetch_} className="flex items-center gap-1.5 text-xs" style={{ color: "var(--accent-cyan)" }}>
        <RefreshCw className="w-3 h-3" /> Refresh
      </button>

      <Section title="Overview">
        <Row icon={<FileCode className="w-3.5 h-3.5" />} label="Python Files" value={String(data.file_count)} />
        <Row icon={<Package className="w-3.5 h-3.5" />} label="Modules" value={String(data.module_count)} />
        <Row icon={<Globe className="w-3.5 h-3.5" />} label="API Endpoints" value={String(data.api_count)} />
        <Row label="Dependencies" value={String(data.dependency_count)} />
      </Section>

      <Section title="Architecture Patterns">
        <div className="flex flex-wrap gap-1.5">
          {data.architecture.patterns.map((p) => (
            <span key={p} className="px-2 py-0.5 rounded text-[11px]" style={{ background: "var(--bg-hover)", color: "var(--accent-cyan)" }}>{p}</span>
          ))}
        </div>
      </Section>

      <Section title="Top Modules">
        {data.top_modules.slice(0, 12).map((m) => (
          <div key={m} className="text-xs font-mono py-0.5" style={{ color: "var(--text-secondary)" }}>{m}</div>
        ))}
      </Section>

      {Object.keys(data.dependencies).length > 0 && (
        <Section title="Dependencies">
          {Object.entries(data.dependencies).map(([cat, deps]) => (
            <div key={cat} className="mb-2">
              <div className="text-[10px] uppercase mb-1" style={{ color: "var(--text-muted)" }}>{cat}</div>
              <div className="flex flex-wrap gap-1">
                {deps.slice(0, 12).map((d) => (
                  <span key={d} className="px-1.5 py-0.5 rounded text-[10px]" style={{ background: "var(--bg-hover)", color: "var(--text-secondary)" }}>{d}</span>
                ))}
                {deps.length > 12 && <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>+{deps.length - 12}</span>}
              </div>
            </div>
          ))}
        </Section>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-[11px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>{title}</h3>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

function Row({ icon, label, value }: { icon?: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="flex items-center gap-1.5" style={{ color: "var(--text-secondary)" }}>{icon}{label}</span>
      <span className="font-mono" style={{ color: "var(--text-primary)" }}>{value}</span>
    </div>
  );
}
