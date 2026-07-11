"use client";

import { useEffect, useState } from "react";
import { RefreshCw, Cpu } from "lucide-react";

interface Model {
  id: string;
  name: string;
  provider_id: string;
  provider_name: string;
  context_length: number;
  capabilities: string[];
}

const CAP_COLORS: Record<string, string> = {
  vision: "var(--accent-purple)",
  reasoning: "var(--accent-amber)",
  tool_calling: "var(--accent-cyan)",
  streaming: "var(--accent-green)",
  long_context: "#ec4899",
  json_mode: "#6366f1",
};

export default function ModelsPanel() {
  const [models, setModels] = useState<Model[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");

  const fetchModels = async () => {
    setLoading(true);
    try {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api"}/models`,
      );
      if (res.ok) setModels(await res.json());
    } catch { /* */ }
    setLoading(false);
  };

  useEffect(() => { fetchModels(); }, []);

  const filtered = models.filter(
    (m) =>
      m.name.toLowerCase().includes(filter.toLowerCase()) ||
      m.provider_name.toLowerCase().includes(filter.toLowerCase()),
  );

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter models..."
          className="flex-1 px-2 py-1.5 rounded text-xs bg-transparent outline-none"
          style={{ border: "1px solid var(--border)", color: "var(--text-primary)" }}
        />
        <button
          onClick={fetchModels}
          className="p-1.5 rounded hover:bg-[var(--bg-hover)]"
          style={{ color: "var(--accent-cyan)" }}
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      {loading ? (
        <div className="text-xs py-4 text-center" style={{ color: "var(--text-muted)" }}>
          Discovering models from providers...
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-xs py-4 text-center" style={{ color: "var(--text-muted)" }}>
          {models.length === 0
            ? "No models found. Add a provider first."
            : "No models match filter."}
        </div>
      ) : (
        filtered.map((m) => (
          <div
            key={`${m.provider_id}-${m.id}`}
            className="p-2.5 rounded-lg cursor-pointer hover:bg-[var(--bg-hover)] transition-colors"
            style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-medium flex items-center gap-1.5" style={{ color: "var(--text-primary)" }}>
                <Cpu className="w-3 h-3" style={{ color: "var(--accent-cyan)" }} />
                {m.name}
              </span>
              <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
                {m.provider_name}
              </span>
            </div>
            {m.context_length > 0 && (
              <div className="text-[10px] mb-1" style={{ color: "var(--text-muted)" }}>
                Context: {(m.context_length / 1000).toFixed(0)}k tokens
              </div>
            )}
            <div className="flex flex-wrap gap-1">
              {m.capabilities.map((cap) => (
                <span
                  key={cap}
                  className="px-1.5 py-0.5 rounded text-[9px] font-medium"
                  style={{
                    background: "var(--bg-hover)",
                    color: CAP_COLORS[cap] || "var(--text-secondary)",
                  }}
                >
                  {cap}
                </span>
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
}
