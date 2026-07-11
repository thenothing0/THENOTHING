"use client";

import { useEffect, useState } from "react";
import { Network, RefreshCw } from "lucide-react";

interface ArchGraph {
  nodes: { id: string; type: string; file_count: number }[];
  edges: { source: string; target: string; type: string }[];
  node_count: number;
  edge_count: number;
  architecture: { patterns: string[]; services: string[] };
}

export default function ArchitecturePanel() {
  const [graph, setGraph] = useState<ArchGraph | null>(null);
  const [loading, setLoading] = useState(true);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  const fetch_ = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/architecture/graph`);
      if (res.ok) setGraph(await res.json());
    } catch {}
    setLoading(false);
  };

  useEffect(() => { fetch_(); }, []);

  if (loading) return <div className="text-xs" style={{ color: "var(--text-muted)" }}>Building architecture graph...</div>;
  if (!graph) return <div className="text-xs" style={{ color: "var(--accent-red)" }}>Backend offline</div>;

  return (
    <div className="space-y-4">
      <button onClick={fetch_} className="flex items-center gap-1.5 text-xs" style={{ color: "var(--accent-cyan)" }}>
        <RefreshCw className="w-3 h-3" /> Refresh
      </button>

      <div className="flex gap-3 text-xs" style={{ color: "var(--text-secondary)" }}>
        <span><strong style={{ color: "var(--accent-cyan)" }}>{graph.node_count}</strong> modules</span>
        <span><strong style={{ color: "var(--accent-purple)" }}>{graph.edge_count}</strong> connections</span>
      </div>

      <Section title="Architecture Patterns">
        <div className="flex flex-wrap gap-1.5">
          {graph.architecture.patterns.map((p) => (
            <span key={p} className="px-2 py-0.5 rounded text-[11px]" style={{ background: "var(--bg-hover)", color: "var(--accent-cyan)" }}>{p}</span>
          ))}
        </div>
      </Section>

      <Section title="Services">
        {graph.architecture.services.slice(0, 20).map((s) => (
          <div key={s} className="text-xs font-mono py-0.5" style={{ color: "var(--text-secondary)" }}>{s}</div>
        ))}
      </Section>

      <Section title="Module Graph">
        {graph.nodes.slice(0, 20).map((n) => {
          const outEdges = graph.edges.filter((e) => e.source === n.id);
          return (
            <div key={n.id} className="py-1.5 border-b" style={{ borderColor: "var(--border)" }}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono" style={{ color: "var(--text-primary)" }}>{n.id}</span>
                <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>{n.file_count} files</span>
              </div>
              {outEdges.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1">
                  {outEdges.map((e) => (
                    <span key={e.target} className="text-[9px] px-1 py-0.5 rounded" style={{ background: "var(--bg-hover)", color: "var(--accent-purple)" }}>
                      → {e.target}
                    </span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-[11px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>{title}</h3>
      <div>{children}</div>
    </div>
  );
}
