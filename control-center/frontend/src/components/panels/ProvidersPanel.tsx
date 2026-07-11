"use client";

import { useEffect, useState } from "react";
import { Plus, Trash2, TestTube, Check, X, Loader2 } from "lucide-react";

interface Provider {
  id: string;
  name: string;
  type: string;
  base_url: string;
  api_key_masked: string;
  enabled: boolean;
  is_local: boolean;
}

const PROVIDER_TYPES = [
  "openai", "anthropic", "gemini", "deepseek", "kimi", "xai",
  "openrouter", "groq", "ollama", "lmstudio", "vllm", "openai_compat",
];

export default function ProvidersPanel() {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<Record<string, { ok: boolean; msg: string }>>({});
  const [form, setForm] = useState({ name: "", type: "openai", api_key: "", base_url: "" });

  const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

  const fetchProviders = async () => {
    try {
      const res = await fetch(`${API}/providers`);
      if (res.ok) setProviders(await res.json());
    } catch { /* offline */ }
  };

  useEffect(() => { fetchProviders(); }, []);

  const addProvider = async () => {
    try {
      await fetch(`${API}/providers`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      setShowAdd(false);
      setForm({ name: "", type: "openai", api_key: "", base_url: "" });
      fetchProviders();
    } catch { /* */ }
  };

  const deleteProvider = async (id: string) => {
    await fetch(`${API}/providers/${id}`, { method: "DELETE" });
    fetchProviders();
  };

  const testProvider = async (id: string) => {
    setTesting(id);
    try {
      const res = await fetch(`${API}/providers/${id}/test`, { method: "POST" });
      const data = await res.json();
      setTestResult((r) => ({
        ...r,
        [id]: { ok: data.ok, msg: data.ok ? `${data.model_count} models` : data.error },
      }));
    } catch (e) {
      setTestResult((r) => ({ ...r, [id]: { ok: false, msg: "connection failed" } }));
    } finally {
      setTesting(null);
    }
  };

  return (
    <div className="space-y-3">
      {/* Add button */}
      <button
        onClick={() => setShowAdd(!showAdd)}
        className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded"
        style={{ background: "var(--bg-hover)", color: "var(--accent-cyan)" }}
      >
        <Plus className="w-3 h-3" /> Add Provider
      </button>

      {/* Add form */}
      {showAdd && (
        <div className="p-3 rounded-lg space-y-2" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
          <input
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="Provider name"
            className="w-full px-2 py-1.5 rounded text-xs bg-transparent outline-none"
            style={{ border: "1px solid var(--border)", color: "var(--text-primary)" }}
          />
          <select
            value={form.type}
            onChange={(e) => setForm({ ...form, type: e.target.value })}
            className="w-full px-2 py-1.5 rounded text-xs outline-none"
            style={{ background: "var(--bg-primary)", border: "1px solid var(--border)", color: "var(--text-primary)" }}
          >
            {PROVIDER_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <input
            value={form.api_key}
            onChange={(e) => setForm({ ...form, api_key: e.target.value })}
            placeholder="API Key (encrypted at rest)"
            type="password"
            className="w-full px-2 py-1.5 rounded text-xs bg-transparent outline-none"
            style={{ border: "1px solid var(--border)", color: "var(--text-primary)" }}
          />
          <input
            value={form.base_url}
            onChange={(e) => setForm({ ...form, base_url: e.target.value })}
            placeholder="Base URL (optional — uses default)"
            className="w-full px-2 py-1.5 rounded text-xs bg-transparent outline-none"
            style={{ border: "1px solid var(--border)", color: "var(--text-primary)" }}
          />
          <div className="flex gap-2">
            <button onClick={addProvider} className="px-3 py-1 rounded text-xs" style={{ background: "var(--accent-cyan)", color: "#000" }}>
              Save
            </button>
            <button onClick={() => setShowAdd(false)} className="px-3 py-1 rounded text-xs" style={{ color: "var(--text-muted)" }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Provider list */}
      {providers.length === 0 && !showAdd && (
        <div className="text-xs py-4 text-center" style={{ color: "var(--text-muted)" }}>
          No providers configured. Add one to get started.
        </div>
      )}

      {providers.map((p) => (
        <div
          key={p.id}
          className="p-3 rounded-lg"
          style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}
        >
          <div className="flex items-center justify-between mb-1.5">
            <div className="flex items-center gap-2">
              <span
                className="w-2 h-2 rounded-full"
                style={{ background: p.enabled ? "var(--accent-green)" : "var(--accent-red)" }}
              />
              <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
                {p.name}
              </span>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={() => testProvider(p.id)}
                className="p-1 rounded hover:bg-[var(--bg-hover)]"
                style={{ color: "var(--text-muted)" }}
                title="Test connection"
              >
                {testing === p.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <TestTube className="w-3.5 h-3.5" />}
              </button>
              <button
                onClick={() => deleteProvider(p.id)}
                className="p-1 rounded hover:bg-[var(--bg-hover)]"
                style={{ color: "var(--accent-red)" }}
                title="Delete"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
          <div className="space-y-0.5 text-[11px]" style={{ color: "var(--text-muted)" }}>
            <div>Type: {p.type}{p.is_local ? " (local)" : ""}</div>
            <div className="truncate">URL: {p.base_url}</div>
            {p.api_key_masked && <div>Key: {p.api_key_masked}</div>}
          </div>
          {testResult[p.id] && (
            <div
              className="flex items-center gap-1 mt-1.5 text-[11px]"
              style={{ color: testResult[p.id].ok ? "var(--accent-green)" : "var(--accent-red)" }}
            >
              {testResult[p.id].ok ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
              {testResult[p.id].msg}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
