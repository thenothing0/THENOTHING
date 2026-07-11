"use client";

import { useEffect, useState } from "react";
import { X } from "lucide-react";

import DashboardPanel from "./panels/DashboardPanel";
import ProvidersPanel from "./panels/ProvidersPanel";
import ModelsPanel from "./panels/ModelsPanel";
import MCPPanel from "./panels/MCPPanel";
import PlaceholderPanel from "./panels/PlaceholderPanel";
import RepositoryPanel from "./panels/RepositoryPanel";
import GitPanel from "./panels/GitPanel";
import RuntimePanel from "./panels/RuntimePanel";
import KnowledgePanel from "./panels/KnowledgePanel";
import ThreatIntelPanel from "./panels/ThreatIntelPanel";
import ReportsPanel from "./panels/ReportsPanel";
import TasksPanel from "./panels/TasksPanel";
import WorkflowsPanel from "./panels/WorkflowsPanel";
import AgentsPanel from "./panels/AgentsPanel";
import PluginsPanel from "./panels/PluginsPanel";
import GuardsPanel from "./panels/GuardsPanel";
import ArchitecturePanel from "./panels/ArchitecturePanel";
import RepoMemoryPanel from "./panels/RepoMemoryPanel";
import HarnessPanel from "./panels/HarnessPanel";
import LogsPanel from "./panels/LogsPanel";
import SettingsPanel from "./panels/SettingsPanel";
import ImpactPanel from "./panels/ImpactPanel";
import MarketplacePanel from "./panels/MarketplacePanel";

interface ContextPanelProps {
  panelId: string;
  onClose: () => void;
}

const PANEL_REGISTRY: Record<string, { component: React.ComponentType; title: string }> = {
  dashboard:     { component: DashboardPanel,    title: "dashboard" },
  providers:     { component: ProvidersPanel,    title: "providers" },
  models:        { component: ModelsPanel,       title: "models" },
  mcp:           { component: MCPPanel,          title: "mcp-inspector" },
  repository:    { component: RepositoryPanel,   title: "repository" },
  git:           { component: GitPanel,          title: "git" },
  runtime:       { component: RuntimePanel,      title: "runtime" },
  knowledge:     { component: KnowledgePanel,    title: "knowledge" },
  "threat-intel": { component: ThreatIntelPanel, title: "threat-intel" },
  reports:       { component: ReportsPanel,      title: "reports" },
  tasks:         { component: TasksPanel,        title: "tasks" },
  workflows:     { component: WorkflowsPanel,    title: "workflows" },
  agents:        { component: AgentsPanel,       title: "agents" },
  plugins:       { component: PluginsPanel,      title: "plugins" },
  marketplace:   { component: MarketplacePanel,  title: "marketplace" },
  guards:        { component: GuardsPanel,       title: "guard-skills" },
  architecture:  { component: ArchitecturePanel, title: "architecture" },
  "repo-memory": { component: RepoMemoryPanel,  title: "repo-memory" },
  impact:        { component: ImpactPanel,       title: "impact-analysis" },
  harness:       { component: HarnessPanel,      title: "harness" },
  logs:          { component: LogsPanel,         title: "logs" },
  settings:      { component: SettingsPanel,     title: "settings" },
};

export default function ContextPanel({ panelId, onClose }: ContextPanelProps) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    requestAnimationFrame(() => setVisible(true));
  }, []);

  if (panelId === "chat") return null;

  const entry = PANEL_REGISTRY[panelId];
  const Panel = entry?.component || PlaceholderPanel;
  const title = entry?.title || panelId;

  return (
    <div
      className="h-full border-l flex flex-col transition-all duration-150"
      style={{
        borderColor: "var(--border)",
        background: "var(--bg-primary)",
        width: visible ? "420px" : "0px",
        minWidth: visible ? "420px" : "0px",
        opacity: visible ? 1 : 0,
      }}
    >
      {/* Terminal-style header */}
      <div
        className="flex items-center justify-between px-3 h-8 shrink-0 border-b"
        style={{ borderColor: "var(--border)" }}
      >
        <span className="text-[11px]" style={{ color: "var(--text-muted)" }}>
          [{title}]
        </span>
        <div className="flex items-center gap-2">
          <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
            esc
          </span>
          <button
            onClick={onClose}
            className="p-0.5 hover:bg-[var(--bg-hover)] transition-colors rounded"
            style={{ color: "var(--text-muted)" }}
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-3 text-[13px]">
        <Panel />
      </div>
    </div>
  );
}
