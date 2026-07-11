"use client";

import { useState, useEffect, useCallback } from "react";
import Sidebar from "./Sidebar";
import ChatPanel from "./ChatPanel";
import ContextPanel from "./ContextPanel";
import CommandPalette from "./CommandPalette";
import BottomBar from "./BottomBar";

export default function Console() {
  const [activePanel, setActivePanel] = useState("chat");
  const [contextPanel, setContextPanel] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);

  const openPanel = useCallback((id: string) => {
    if (id === "chat") {
      setContextPanel(null);
      setActivePanel("chat");
    } else {
      setContextPanel(id);
      setActivePanel(id);
    }
  }, []);

  const closePanel = useCallback(() => {
    setContextPanel(null);
    setActivePanel("chat");
  }, []);

  const handleNavSelect = useCallback((id: string) => {
    openPanel(id);
  }, [openPanel]);

  const handleCommandSelect = useCallback((command: string) => {
    openPanel(command);
  }, [openPanel]);

  const handleChatCommand = useCallback((panelId: string) => {
    openPanel(panelId);
  }, [openPanel]);

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.shiftKey && e.key === "P") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
      if (e.key === "Escape" && contextPanel) {
        closePanel();
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [contextPanel, closePanel]);

  return (
    <div className="flex flex-col h-screen" style={{ background: "var(--bg-primary)" }}>
      <div className="flex flex-1 min-h-0">
        {/* Minimal sidebar — conversations only */}
        <Sidebar activePanel={activePanel} onSelect={handleNavSelect} />

        {/* Chat — always visible, fills available space */}
        <div className="flex-1 min-w-0">
          <ChatPanel onCommand={handleChatCommand} />
        </div>

        {/* Context panel — temporary drawer, slides in from right */}
        {contextPanel && (
          <ContextPanel
            panelId={contextPanel}
            onClose={closePanel}
          />
        )}
      </div>

      {/* Bottom status bar */}
      <BottomBar />

      {/* Command palette overlay */}
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onSelect={handleCommandSelect}
      />
    </div>
  );
}
