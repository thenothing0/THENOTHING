"use client";

import { Construction } from "lucide-react";

export default function PlaceholderPanel() {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <Construction className="w-8 h-8 mb-3" style={{ color: "var(--text-muted)" }} />
      <h3 className="text-sm font-medium mb-1" style={{ color: "var(--text-secondary)" }}>
        Coming Soon
      </h3>
      <p className="text-xs max-w-[250px]" style={{ color: "var(--text-muted)" }}>
        This panel will be built in Phase 2. The backend API endpoint is ready.
      </p>
    </div>
  );
}
