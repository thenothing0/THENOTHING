const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
  return res.json();
}

export const api = {
  health: () => request<{ status: string }>("/health"),

  providers: {
    list: () => request<Provider[]>("/providers"),
    create: (data: ProviderCreate) =>
      request<Provider>("/providers", { method: "POST", body: JSON.stringify(data) }),
    update: (id: string, data: Partial<ProviderCreate>) =>
      request<Provider>(`/providers/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
    delete: (id: string) =>
      request(`/providers/${id}`, { method: "DELETE" }),
    test: (id: string) =>
      request<{ ok: boolean; model_count?: number; error?: string }>(`/providers/${id}/test`, { method: "POST" }),
  },

  models: {
    list: (providerId?: string) =>
      request<ModelInfo[]>(`/models${providerId ? `?provider_id=${providerId}` : ""}`),
  },

  dashboard: {
    stats: () => request<DashboardStats>("/dashboard/stats"),
  },

  mcp: {
    servers: () => request<MCPServer[]>("/mcp/servers"),
    toolCount: () => request<{ count: number }>("/mcp/tools/count"),
  },

  commands: {
    list: () => request<CommandEntry[]>("/commands"),
    search: (q: string) => request<CommandEntry[]>(`/commands/search?q=${encodeURIComponent(q)}`),
  },

  chat: {
    send: (messages: ChatMessage[], providerId?: string, modelId?: string) =>
      request<ChatMessage>("/chat", {
        method: "POST",
        body: JSON.stringify({ messages, provider_id: providerId, model_id: modelId }),
      }),
    history: (limit = 50) => request<ChatMessage[]>(`/chat/history?limit=${limit}`),
    clear: () => request("/chat/history", { method: "DELETE" }),
  },
};

export interface Provider {
  id: string;
  name: string;
  type: string;
  base_url: string;
  api_key_masked: string;
  enabled: boolean;
  is_local: boolean;
  status: string;
}

export interface ProviderCreate {
  name: string;
  type: string;
  base_url?: string;
  api_key?: string;
  enabled?: boolean;
  is_local?: boolean;
}

export interface ModelInfo {
  id: string;
  name: string;
  provider_id: string;
  provider_name: string;
  context_length: number;
  capabilities: string[];
}

export interface DashboardStats {
  repo_name: string;
  branch: string;
  last_commit: string;
  modified_files: number;
  untracked_files: number;
  tech_stack: string[];
  mcp_tool_count: number;
  hydra_subsystems: number;
  knowledge_health: number | null;
  runtime_status: string;
}

export interface MCPServer {
  name: string;
  command: string;
  args: string[];
  status: string;
  tool_count: number;
}

export interface CommandEntry {
  name: string;
  description: string;
  category: string;
  shortcut: string;
}

export interface ChatMessage {
  role: string;
  content: string;
  tool_calls?: Record<string, unknown>[];
}
