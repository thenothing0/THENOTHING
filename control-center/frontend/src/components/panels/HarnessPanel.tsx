"use client";

import { useState } from "react";
import { Wrench, Play, Loader2, CheckCircle, AlertTriangle } from "lucide-react";

export default function HarnessPanel() {
  const [context, setContext] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  const activate = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/harness/activate`, { method: "POST" });
      if (res.ok) setContext(await res.json());
    } catch {}
    setLoading(false);
  };

  if (!context) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-center">
        <Wrench className="w-10 h-10 mb-3" style={{ color: "var(--text-muted)" }} />
        <h3 className="text-sm font-medium mb-2" style={{ color: "var(--text-primary)" }}>Harness Engineering</h3>
        <p className="text-xs mb-4 max-w-[280px]" style={{ color: "var(--text-muted)" }}>
          Activates repository analysis, architecture detection, guard pipeline, and engineering context — all in one command.
        </p>
        <button
          onClick={activate}
          disabled={loading}
          className="flex items-center gap-1.5 px-4 py-2 rounded text-xs"
          style={{ background: "var(--accent-cyan)", color: "#000" }}
        >
          {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
          {loading ? "Analyzing..." : "Activate /harness"}
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <CheckCircle className="w-4 h-4" style={{ color: "var(--accent-green)" }} />
        <span className="text-sm font-medium" style={{ color: "var(--accent-green)" }}>Harness Active</span>
      </div>

      {/* Repository */}
      <Section title="Repository">
        <Row label="Project" value={context.repository?.name} />
        <Row label="Branch" value={context.repository?.branch} />
        <Row label="Modified" value={String(context.repository?.modified_files || 0)} />
      </Section>

      {/* Active Task */}
      {context.active_task && (
        <Section title="Active Task">
          <Row label="Branch" value={context.active_task.branch} />
          <Row label="Type" value={context.active_task.inferred_task} />
          <Row label="Changed" value={`${context.active_task.changed_count} files`} />
          {context.active_task.domains?.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1">
              {context.active_task.domains.map((d: string) => (
                <span key={d} className="px-1.5 py-0.5 rounded text-[10px]" style={{ background: "var(--bg-hover)", color: "var(--accent-cyan)" }}>{d}</span>
              ))}
            </div>
          )}
        </Section>
      )}

      {/* Tech Stack */}
      <Section title="Technologies">
        <div className="flex flex-wrap gap-1.5">
          {context.tech_stack?.map((t: string) => (
            <span key={t} className="px-2 py-0.5 rounded text-[11px]" style={{ background: "var(--bg-hover)", color: "var(--text-secondary)" }}>{t}</span>
          ))}
        </div>
      </Section>

      {/* Guards */}
      {context.guards && (
        <Section title="Guard Pipeline">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-xl font-bold" style={{ color: context.guards.overall_score >= 80 ? "var(--accent-green)" : context.guards.overall_score >= 50 ? "var(--accent-amber)" : "var(--accent-red)" }}>
              {context.guards.overall_score}
            </span>
            <span className="text-[11px]" style={{ color: "var(--text-muted)" }}>
              {context.guards.passed}✓ {context.guards.warned}⚠ {context.guards.failed}✗
            </span>
          </div>
          {context.guards.guards?.slice(0, 10).map((g: any) => (
            <div key={g.name} className="flex items-center justify-between text-xs py-0.5">
              <span style={{ color: "var(--text-secondary)" }}>{g.name.replace(/_/g, " ")}</span>
              <span style={{ color: g.status === "pass" ? "var(--accent-green)" : g.status === "warn" ? "var(--accent-amber)" : "var(--accent-red)" }}>
                {g.score}
              </span>
            </div>
          ))}
        </Section>
      )}

      {/* Repo Memory */}
      <Section title="Repository Memory">
        <Row label="APIs" value={String(context.apis?.count || 0)} />
        <Row label="Architecture" value={context.architecture?.patterns?.join(", ") || "none"} />
      </Section>

      <button
        onClick={activate}
        className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded w-full justify-center"
        style={{ background: "var(--bg-hover)", color: "var(--accent-cyan)" }}
      >
        <Wrench className="w-3 h-3" /> Refresh Context
      </button>
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

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span style={{ color: "var(--text-secondary)" }}>{label}</span>
      <span className="font-mono truncate max-w-[200px]" style={{ color: "var(--text-primary)" }}>{value}</span>
    </div>
  );
}
