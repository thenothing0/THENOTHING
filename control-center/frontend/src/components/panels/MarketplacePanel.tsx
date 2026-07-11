"use client";

import { Store } from "lucide-react";

export default function MarketplacePanel() {
  return (
    <div className="space-y-4">
      <div className="p-3 rounded-lg" style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 mb-2">
          <Store className="w-4 h-4" style={{ color: "var(--accent-cyan)" }} />
          <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>Marketplace</span>
        </div>
        <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
          Discover and install plugins, skills, and capabilities from the HYDRA ecosystem. Marketplace content is verified and signed.
        </div>
      </div>
      <div className="text-xs text-center py-4" style={{ color: "var(--text-muted)" }}>
        Marketplace integration coming in Phase 3. Use <span className="font-mono" style={{ color: "var(--accent-cyan)" }}>/plugins</span> to manage installed plugins.
      </div>
    </div>
  );
}
