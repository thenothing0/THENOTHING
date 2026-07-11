"use client";

import { useEffect, useState } from "react";
import { Activity, Server, Database, RefreshCw } from "lucide-react";

export default function RuntimePanel() {
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  const fetch_ = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/dashboard/health`);
      if (res.ok) setHealth(await res.json());
    } catch {}
    setLoading(false);
  };

  useEffect(() => { fetch_(); }, []);

  if (loading) return <div className="text-xs" style={{ color: "var(--text-muted)" }}>Checking runtime...</div>;
  if (!health) return <div className="text-xs" style={{ color: "var(--accent-red)" }}>Backend offline</div>;

  const runtime = health.runtime || {};

  return (
    <div className="space-y-4">
      <button onClick={fetch_} className="flex items-center gap-1.5 text-xs" style={{ color: "var(--accent-cyan)" }}>
        <RefreshCw className="w-3 h-3" /> Refresh
      </button>

      <Section title="Services">
        <StatusRow icon={<Server className="w-3.5 h-3.5" />} label="Docker Compose" status={runtime.docker || "unknown"} />
        <StatusRow icon={<Activity className="w-3.5 h-3.5" />} label="MCP Server" status={runtime.mcp || "unknown"} />
        <StatusRow icon={<Database className="w-3.5 h-3.5" />} label="Knowledge OS" status={health.knowledge?.status || "unknown"} />
      </Section>

      <Section title="Knowledge Base">
        <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
          {health.knowledge?.pages || 0} wiki pages indexed
        </div>
      </Section>

      <Section title="Tests">
        <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
          {health.tests?.file_count || 0} test files discovered
        </div>
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-[11px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-muted)" }}>{title}</h3>
      <div className="space-y-1.5">{children}</div>
    </div>
  );
}

function StatusRow({ icon, label, status }: { icon: React.ReactNode; label: string; status: string }) {
  const color = status === "running" || status === "available" || status === "healthy"
    ? "var(--accent-green)"
    : status === "stopped" || status === "missing"
      ? "var(--accent-red)"
      : "var(--accent-amber)";
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="flex items-center gap-1.5" style={{ color: "var(--text-secondary)" }}>{icon}{label}</span>
      <span className="flex items-center gap-1.5">
        <span className="w-2 h-2 rounded-full" style={{ background: color }} />
        <span style={{ color }}>{status}</span>
      </span>
    </div>
  );
}
