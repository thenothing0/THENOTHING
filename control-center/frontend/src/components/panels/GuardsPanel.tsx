"use client";

import { useState } from "react";
import { ShieldCheck, Play, Loader2, CheckCircle, AlertTriangle, XCircle } from "lucide-react";

interface GuardResult {
  name: string;
  status: string;
  score: number;
  issue_count: number;
  issues: { file: string; line: number; msg: string }[];
}

interface PipelineResult {
  guards: GuardResult[];
  overall_score: number;
  overall_status: string;
  passed: number;
  warned: number;
  failed: number;
}

export default function GuardsPanel() {
  const [result, setResult] = useState<PipelineResult | null>(null);
  const [running, setRunning] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  const runPipeline = async () => {
    setRunning(true);
    try {
      const res = await fetch(`${API}/guards/run`, { method: "POST" });
      if (res.ok) setResult(await res.json());
    } catch {}
    setRunning(false);
  };

  return (
    <div className="space-y-4">
      <button
        onClick={runPipeline}
        disabled={running}
        className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded"
        style={{ background: "var(--accent-cyan)", color: "#000" }}
      >
        {running ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
        {running ? "Running Pipeline..." : "Run Guard Pipeline"}
      </button>

      {result && (
        <>
          {/* Overall score */}
          <div className="p-3 rounded-lg text-center" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
            <div className="text-3xl font-bold" style={{ color: result.overall_score >= 80 ? "var(--accent-green)" : result.overall_score >= 50 ? "var(--accent-amber)" : "var(--accent-red)" }}>
              {result.overall_score}
            </div>
            <div className="text-[11px] mt-1" style={{ color: "var(--text-muted)" }}>
              {result.passed} passed · {result.warned} warned · {result.failed} failed
            </div>
          </div>

          {/* Individual guards */}
          {result.guards.map((g) => (
            <div
              key={g.name}
              className="rounded-lg overflow-hidden"
              style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}
            >
              <button
                onClick={() => setExpanded(expanded === g.name ? null : g.name)}
                className="flex items-center justify-between w-full px-3 py-2 text-left hover:bg-[var(--bg-hover)]"
              >
                <span className="flex items-center gap-2 text-xs">
                  {g.status === "pass" ? <CheckCircle className="w-3.5 h-3.5" style={{ color: "var(--accent-green)" }} /> :
                   g.status === "warn" ? <AlertTriangle className="w-3.5 h-3.5" style={{ color: "var(--accent-amber)" }} /> :
                   <XCircle className="w-3.5 h-3.5" style={{ color: "var(--accent-red)" }} />}
                  <span style={{ color: "var(--text-primary)" }}>{g.name.replace(/_/g, " ")}</span>
                </span>
                <span className="flex items-center gap-2">
                  <span className="text-[11px] font-mono" style={{ color: "var(--text-muted)" }}>{g.score}</span>
                  {g.issue_count > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: "var(--bg-hover)", color: "var(--accent-amber)" }}>{g.issue_count}</span>}
                </span>
              </button>
              {expanded === g.name && g.issues.length > 0 && (
                <div className="px-3 pb-2 space-y-1 border-t" style={{ borderColor: "var(--border)" }}>
                  {g.issues.slice(0, 10).map((issue, i) => (
                    <div key={i} className="text-[11px] py-0.5" style={{ color: "var(--text-muted)" }}>
                      {issue.file && <span className="font-mono" style={{ color: "var(--text-secondary)" }}>{issue.file}{issue.line > 0 ? `:${issue.line}` : ""} </span>}
                      {issue.msg}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </>
      )}

      {!result && !running && (
        <div className="text-xs text-center py-6" style={{ color: "var(--text-muted)" }}>
          <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-30" />
          Run the guard pipeline to analyze code quality, security, architecture, and more.
        </div>
      )}
    </div>
  );
}
