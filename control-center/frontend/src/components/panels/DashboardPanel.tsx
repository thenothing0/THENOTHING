"use client";

import { useEffect, useState } from "react";
import { GitBranch, Server, Cpu, FileText, Activity, RefreshCw } from "lucide-react";

interface Stats {
  repo_name: string;
  branch: string;
  last_commit: string;
  modified_files: number;
  untracked_files: number;
  tech_stack: string[];
  mcp_tool_count: number;
  hydra_subsystems: number;
  runtime_status: string;
}

export default function DashboardPanel() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = async () => {
    setLoading(true);
    try {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api"}/dashboard/stats`,
      );
      if (res.ok) setStats(await res.json());
    } catch {
      /* offline */
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  if (loading && !stats) {
    return <div className="text-sm" style={{ color: "var(--text-muted)" }}>Loading dashboard...</div>;
  }

  if (!stats) {
    return (
      <div className="text-sm" style={{ color: "var(--accent-red)" }}>
        Backend offline. Start with: <code className="text-xs">uvicorn control-center.backend.main:app</code>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Refresh */}
      <button
        onClick={fetchStats}
        className="flex items-center gap-1.5 text-xs hover:opacity-80"
        style={{ color: "var(--accent-cyan)" }}
      >
        <RefreshCw className="w-3 h-3" /> Refresh
      </button>

      {/* Repository */}
      <Section title="Repository">
        <Row icon={<Cpu className="w-3.5 h-3.5" />} label="Project" value={stats.repo_name} />
        <Row icon={<GitBranch className="w-3.5 h-3.5" />} label="Branch" value={stats.branch} />
        <Row icon={<FileText className="w-3.5 h-3.5" />} label="Last Commit" value={stats.last_commit} />
        <Row label="Modified" value={String(stats.modified_files)} />
        <Row label="Untracked" value={String(stats.untracked_files)} />
      </Section>

      {/* Platform */}
      <Section title="HYDRA Platform">
        <Row icon={<Activity className="w-3.5 h-3.5" />} label="Runtime" value={stats.runtime_status} valueColor="var(--accent-green)" />
        <Row icon={<Server className="w-3.5 h-3.5" />} label="MCP Tools" value={String(stats.mcp_tool_count)} valueColor="var(--accent-cyan)" />
        <Row label="Subsystems" value={String(stats.hydra_subsystems)} />
      </Section>

      {/* Tech Stack */}
      <Section title="Technology Stack">
        <div className="flex flex-wrap gap-1.5">
          {stats.tech_stack.map((t) => (
            <span
              key={t}
              className="px-2 py-0.5 rounded text-[11px]"
              style={{ background: "var(--bg-hover)", color: "var(--text-secondary)" }}
            >
              {t}
            </span>
          ))}
        </div>
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3
        className="text-[11px] font-semibold uppercase tracking-wider mb-2"
        style={{ color: "var(--text-muted)" }}
      >
        {title}
      </h3>
      <div className="space-y-1.5">{children}</div>
    </div>
  );
}

function Row({
  icon,
  label,
  value,
  valueColor,
}: {
  icon?: React.ReactNode;
  label: string;
  value: string;
  valueColor?: string;
}) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="flex items-center gap-1.5" style={{ color: "var(--text-secondary)" }}>
        {icon}
        {label}
      </span>
      <span className="font-mono truncate max-w-[200px]" style={{ color: valueColor || "var(--text-primary)" }}>
        {value}
      </span>
    </div>
  );
}
