"use client";

import { useState, useEffect, useRef } from "react";

interface Command {
  name: string;
  description: string;
}

const COMMANDS: Command[] = [
  { name: "/harness", description: "engineering workspace" },
  { name: "/providers", description: "manage providers" },
  { name: "/models", description: "browse models" },
  { name: "/mcp", description: "mcp inspector" },
  { name: "/knowledge", description: "knowledge explorer" },
  { name: "/threat-intel", description: "threat intelligence" },
  { name: "/repository", description: "repository context" },
  { name: "/repo-memory", description: "repo memory index" },
  { name: "/architecture", description: "architecture graph" },
  { name: "/guards", description: "guard pipeline" },
  { name: "/runtime", description: "runtime monitor" },
  { name: "/git", description: "git operations" },
  { name: "/reports", description: "reports" },
  { name: "/tasks", description: "task manager" },
  { name: "/workflows", description: "workflow builder" },
  { name: "/agents", description: "agent orchestration" },
  { name: "/plugins", description: "installed plugins" },
  { name: "/impact", description: "impact analysis" },
  { name: "/logs", description: "log viewer" },
  { name: "/settings", description: "settings" },
  { name: "/dashboard", description: "dashboard overview" },
  { name: "/clear", description: "clear conversation" },
  { name: "/help", description: "list commands" },
];

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onSelect: (command: string) => void;
}

export default function CommandPalette({ open, onClose, onSelect }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIdx(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  if (!open) return null;

  const filtered = COMMANDS.filter(
    (c) =>
      c.name.includes(query.toLowerCase()) ||
      c.description.includes(query.toLowerCase()),
  );

  const handleSelect = (cmd: Command) => {
    const id = cmd.name.slice(1);
    onSelect(id);
    onClose();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      onClose();
    } else if (e.key === "Enter" && filtered.length > 0) {
      handleSelect(filtered[selectedIdx]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIdx((i) => Math.min(i + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIdx((i) => Math.max(i - 1, 0));
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]"
      style={{ background: "rgba(0,0,0,0.5)" }}
      onClick={onClose}
    >
      <div
        className="w-[440px] border overflow-hidden"
        style={{ background: "var(--bg-primary)", borderColor: "var(--border)" }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Input */}
        <div
          className="flex items-center gap-2 px-3 h-9 border-b"
          style={{ borderColor: "var(--border)" }}
        >
          <span className="text-[11px]" style={{ color: "var(--text-muted)" }}>
            &gt;
          </span>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIdx(0);
            }}
            onKeyDown={handleKeyDown}
            placeholder="search commands..."
            className="flex-1 bg-transparent outline-none text-[13px]"
            style={{ color: "var(--text-primary)", caretColor: "var(--accent-cyan)" }}
            spellCheck={false}
          />
          <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
            esc
          </span>
        </div>

        {/* Results */}
        <div className="max-h-[280px] overflow-y-auto">
          {filtered.map((cmd, i) => (
            <button
              key={cmd.name}
              onClick={() => handleSelect(cmd)}
              className="flex items-center w-full px-3 h-7 text-left text-[13px] transition-colors"
              style={{
                background: i === selectedIdx ? "var(--bg-hover)" : "transparent",
                color: i === selectedIdx ? "var(--text-primary)" : "var(--text-secondary)",
              }}
            >
              <span
                className="w-28 shrink-0"
                style={{ color: i === selectedIdx ? "var(--accent-cyan)" : "var(--text-secondary)" }}
              >
                {cmd.name}
              </span>
              <span style={{ color: "var(--text-muted)" }}>{cmd.description}</span>
            </button>
          ))}
          {filtered.length === 0 && (
            <div className="px-3 py-4 text-center text-[13px]" style={{ color: "var(--text-muted)" }}>
              no matches
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
