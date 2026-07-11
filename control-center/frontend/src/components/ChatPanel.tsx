"use client";

import { useState, useRef, useEffect } from "react";
import { Loader2 } from "lucide-react";

interface Message {
  role: "user" | "assistant" | "system";
  content: string;
  timestamp?: number;
}

const COMMAND_PANEL_MAP: Record<string, string> = {
  "/harness": "harness",
  "/providers": "providers",
  "/models": "models",
  "/mcp": "mcp",
  "/knowledge": "knowledge",
  "/threat-intel": "threat-intel",
  "/runtime": "runtime",
  "/repository": "repository",
  "/repo-memory": "repo-memory",
  "/architecture": "architecture",
  "/guards": "guards",
  "/git": "git",
  "/reports": "reports",
  "/report": "reports",
  "/tasks": "tasks",
  "/workflows": "workflows",
  "/workflow": "workflows",
  "/agents": "agents",
  "/plugins": "plugins",
  "/marketplace": "marketplace",
  "/impact": "impact",
  "/logs": "logs",
  "/settings": "settings",
  "/dashboard": "dashboard",
};

interface ChatPanelProps {
  onCommand?: (panelId: string) => void;
}

export default function ChatPanel({ onCommand }: ChatPanelProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "system",
      content: "HYDRA Control Center v1.0\nType /help for commands. Ctrl+Shift+P for palette.",
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [historyIdx, setHistoryIdx] = useState(-1);
  const [cmdHistory, setCmdHistory] = useState<string[]>([]);
  const endRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSend = async () => {
    const text = input.trim();
    if (!text || loading) return;

    setCmdHistory((prev) => [text, ...prev]);
    setHistoryIdx(-1);

    const userMsg: Message = { role: "user", content: text, timestamp: Date.now() };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    if (text.startsWith("/")) {
      const parts = text.split(" ");
      const cmd = parts[0].toLowerCase();
      const panelId = COMMAND_PANEL_MAP[cmd];

      if (panelId) {
        setMessages((prev) => [
          ...prev,
          { role: "system", content: `→ opening ${panelId}`, timestamp: Date.now() },
        ]);
        onCommand?.(panelId);
      } else if (cmd === "/help") {
        const cmds = Object.keys(COMMAND_PANEL_MAP).sort();
        const lines = cmds.map((c) => `  ${c}`).join("\n");
        setMessages((prev) => [
          ...prev,
          {
            role: "system",
            content: `Available commands:\n${lines}\n\n  /help     show this message\n  /clear    clear conversation`,
            timestamp: Date.now(),
          },
        ]);
      } else if (cmd === "/clear") {
        setMessages([
          { role: "system", content: "Conversation cleared.", timestamp: Date.now() },
        ]);
      } else {
        setMessages((prev) => [
          ...prev,
          { role: "system", content: `unknown command: ${cmd}\ntype /help for available commands`, timestamp: Date.now() },
        ]);
      }
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api"}/chat`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            messages: [{ role: "user", content: text }],
          }),
        },
      );
      const data = await res.json();
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: data.content, timestamp: Date.now() },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "system", content: "error: connection failed — is backend running on :8081?", timestamp: Date.now() },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleSend();
    }
    if (e.key === "ArrowUp" && cmdHistory.length > 0) {
      e.preventDefault();
      const next = Math.min(historyIdx + 1, cmdHistory.length - 1);
      setHistoryIdx(next);
      setInput(cmdHistory[next]);
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIdx <= 0) {
        setHistoryIdx(-1);
        setInput("");
      } else {
        const next = historyIdx - 1;
        setHistoryIdx(next);
        setInput(cmdHistory[next]);
      }
    }
    if (e.key === "l" && e.ctrlKey) {
      e.preventDefault();
      setMessages([
        { role: "system", content: "Conversation cleared.", timestamp: Date.now() },
      ]);
    }
  };

  return (
    <div
      className="flex flex-col h-full"
      style={{ background: "var(--bg-primary)" }}
      onClick={() => inputRef.current?.focus()}
    >
      {/* Terminal output */}
      <div className="flex-1 overflow-y-auto px-4 py-3">
        {messages.map((msg, i) => (
          <div key={i} className="mb-1">
            {msg.role === "system" ? (
              <pre
                className="whitespace-pre-wrap text-[13px] leading-relaxed py-0.5"
                style={{ color: "var(--system-color)" }}
              >
                {msg.content}
              </pre>
            ) : msg.role === "user" ? (
              <div className="flex items-start gap-0 py-0.5">
                <span
                  className="text-[13px] shrink-0 select-none"
                  style={{ color: "var(--prompt-color)" }}
                >
                  &gt;{" "}
                </span>
                <pre
                  className="whitespace-pre-wrap text-[13px] leading-relaxed"
                  style={{ color: "var(--text-primary)" }}
                >
                  {msg.content}
                </pre>
              </div>
            ) : (
              <pre
                className="whitespace-pre-wrap text-[13px] leading-relaxed py-1 pl-3"
                style={{
                  color: "var(--output-color)",
                  borderLeft: "2px solid var(--border)",
                }}
              >
                {msg.content}
              </pre>
            )}
          </div>
        ))}
        {loading && (
          <div
            className="flex items-center gap-2 text-[13px] py-0.5"
            style={{ color: "var(--text-muted)" }}
          >
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            <span>processing...</span>
          </div>
        )}
        <div ref={endRef} />
      </div>

      {/* Command prompt */}
      <div
        className="shrink-0 border-t px-4 py-2"
        style={{ borderColor: "var(--border)" }}
      >
        <div className="flex items-center gap-0">
          <span
            className="text-[13px] shrink-0 select-none"
            style={{ color: "var(--prompt-color)" }}
          >
            &gt;{" "}
          </span>
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            className="flex-1 bg-transparent outline-none text-[13px]"
            style={{ color: "var(--text-primary)", caretColor: "var(--prompt-color)" }}
            spellCheck={false}
            autoComplete="off"
          />
        </div>
        <div
          className="flex items-center gap-4 mt-1 text-[11px] select-none"
          style={{ color: "var(--text-muted)" }}
        >
          <span>enter send</span>
          <span>↑↓ history</span>
          <span>ctrl+l clear</span>
          <span>ctrl+shift+p palette</span>
        </div>
      </div>
    </div>
  );
}
