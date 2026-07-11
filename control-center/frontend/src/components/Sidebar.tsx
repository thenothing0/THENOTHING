"use client";

import { useState } from "react";
import { cn } from "@/lib/utils";
import {
  Crosshair,
  Plus,
  MessageSquare,
  Settings,
  PanelLeftOpen,
  PanelLeftClose,
} from "lucide-react";

interface Session {
  id: string;
  title: string;
  timestamp: number;
}

interface SidebarProps {
  activePanel: string;
  onSelect: (id: string) => void;
}

export default function Sidebar({ activePanel, onSelect }: SidebarProps) {
  const [expanded, setExpanded] = useState(false);
  const [sessions] = useState<Session[]>([
    { id: "current", title: "Current Session", timestamp: Date.now() },
  ]);

  return (
    <aside
      className={cn(
        "flex flex-col h-full border-r transition-all duration-150",
        expanded ? "w-48" : "w-10",
      )}
      style={{ borderColor: "var(--border)", background: "var(--bg-primary)" }}
    >
      {/* Toggle */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center justify-center h-8 shrink-0 hover:bg-[var(--bg-hover)] transition-colors"
        style={{ color: "var(--text-muted)" }}
        title={expanded ? "Collapse" : "Expand"}
      >
        {expanded ? (
          <PanelLeftClose className="w-3.5 h-3.5" />
        ) : (
          <PanelLeftOpen className="w-3.5 h-3.5" />
        )}
      </button>

      {/* New conversation */}
      <button
        onClick={() => onSelect("chat")}
        className="flex items-center gap-2 mx-1 px-2 py-1.5 rounded hover:bg-[var(--bg-hover)] transition-colors"
        style={{ color: "var(--accent-cyan)" }}
        title="New conversation"
      >
        <Plus className="w-3.5 h-3.5 shrink-0" />
        {expanded && <span className="text-xs truncate">New</span>}
      </button>

      {/* Sessions */}
      <nav className="flex-1 overflow-y-auto mt-2 mx-1">
        {sessions.map((session) => (
          <button
            key={session.id}
            onClick={() => onSelect("chat")}
            className={cn(
              "flex items-center gap-2 w-full px-2 py-1.5 rounded text-left transition-colors",
              "hover:bg-[var(--bg-hover)]",
              session.id === "current" && "bg-[var(--bg-hover)]",
            )}
            style={{
              color: session.id === "current" ? "var(--text-primary)" : "var(--text-muted)",
            }}
            title={session.title}
          >
            <MessageSquare className="w-3 h-3 shrink-0" />
            {expanded && (
              <span className="text-[11px] truncate">{session.title}</span>
            )}
          </button>
        ))}
      </nav>

      {/* Settings */}
      <div className="border-t mx-1 pt-1 pb-1" style={{ borderColor: "var(--border)" }}>
        <button
          onClick={() => onSelect("settings")}
          className="flex items-center gap-2 w-full px-2 py-1.5 rounded hover:bg-[var(--bg-hover)] transition-colors"
          style={{
            color: activePanel === "settings" ? "var(--text-primary)" : "var(--text-muted)",
          }}
          title="Settings"
        >
          <Settings className="w-3 h-3 shrink-0" />
          {expanded && <span className="text-[11px]">Settings</span>}
        </button>
      </div>
    </aside>
  );
}
