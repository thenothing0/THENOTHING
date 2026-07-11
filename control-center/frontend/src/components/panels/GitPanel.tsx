"use client";

import { useEffect, useState } from "react";
import { GitBranch, GitCommit, RefreshCw } from "lucide-react";

interface GitHealth {
  git: {
    recent_commits: string[];
    branches: string[];
    stashes: string[];
  };
}

export default function GitPanel() {
  const [data, setData] = useState<GitHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  const fetch_ = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/dashboard/health`);
      if (res.ok) setData(await res.json());
    } catch {}
    setLoading(false);
  };

  useEffect(() => { fetch_(); }, []);

  if (loading) return <div className="text-xs" style={{ color: "var(--text-muted)" }}>Loading git status...</div>;
  if (!data) return <div className="text-xs" style={{ color: "var(--accent-red)" }}>Backend offline</div>;

  return (
    <div className="space-y-4">
      <button onClick={fetch_} className="flex items-center gap-1.5 text-xs" style={{ color: "var(--accent-cyan)" }}>
        <RefreshCw className="w-3 h-3" /> Refresh
      </button>

      <Section title="Recent Commits">
        {data.git.recent_commits?.map((c, i) => (
          <div key={i} className="flex items-start gap-2 text-xs py-1">
            <GitCommit className="w-3 h-3 mt-0.5 shrink-0" style={{ color: "var(--accent-cyan)" }} />
            <span className="font-mono" style={{ color: "var(--text-secondary)" }}>{c}</span>
          </div>
        ))}
      </Section>

      <Section title="Branches">
        {data.git.branches?.map((b, i) => (
          <div key={i} className="flex items-center gap-2 text-xs py-0.5">
            <GitBranch className="w-3 h-3 shrink-0" style={{ color: b.includes("*") ? "var(--accent-green)" : "var(--text-muted)" }} />
            <span className="font-mono" style={{ color: b.includes("*") ? "var(--accent-green)" : "var(--text-secondary)" }}>{b}</span>
          </div>
        ))}
      </Section>

      {data.git.stashes?.length > 0 && (
        <Section title="Stashes">
          {data.git.stashes.map((s, i) => (
            <div key={i} className="text-xs font-mono py-0.5" style={{ color: "var(--text-muted)" }}>{s}</div>
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
      <div>{children}</div>
    </div>
  );
}
