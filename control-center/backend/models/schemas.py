from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ProviderType(str, Enum):
    openai = "openai"
    anthropic = "anthropic"
    gemini = "gemini"
    deepseek = "deepseek"
    kimi = "kimi"
    xai = "xai"
    openrouter = "openrouter"
    groq = "groq"
    ollama = "ollama"
    lmstudio = "lmstudio"
    vllm = "vllm"
    openai_compat = "openai_compat"


class ProviderCreate(BaseModel):
    name: str
    type: ProviderType
    base_url: str = ""
    api_key: str = ""
    enabled: bool = True
    is_local: bool = False


class ProviderUpdate(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    enabled: Optional[bool] = None


class ProviderOut(BaseModel):
    id: str
    name: str
    type: ProviderType
    base_url: str
    api_key_masked: str
    enabled: bool
    is_local: bool
    status: str = "unknown"


class ModelInfo(BaseModel):
    id: str
    name: str
    provider_id: str
    provider_name: str
    context_length: int = 0
    capabilities: list[str] = Field(default_factory=list)


class ModelSettings(BaseModel):
    temperature: float = 0.7
    top_p: float = 1.0
    max_tokens: int = 4096
    stream: bool = True
    system_prompt: str = ""


class ChatMessage(BaseModel):
    role: str
    content: str
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    provider_id: Optional[str] = None
    model_id: Optional[str] = None
    settings: ModelSettings = Field(default_factory=ModelSettings)


class MCPServerInfo(BaseModel):
    name: str
    command: str
    args: list[str] = Field(default_factory=list)
    status: str = "unknown"
    tool_count: int = 0
    env: dict[str, str] = Field(default_factory=dict)


class DashboardStats(BaseModel):
    repo_name: str = ""
    branch: str = ""
    last_commit: str = ""
    modified_files: int = 0
    untracked_files: int = 0
    tech_stack: list[str] = Field(default_factory=list)
    mcp_tool_count: int = 0
    hydra_subsystems: int = 0
    knowledge_health: Optional[float] = None
    runtime_status: str = "unknown"


class PanelType(str, Enum):
    repository = "repository"
    git = "git"
    providers = "providers"
    models = "models"
    knowledge = "knowledge"
    threat_intel = "threat_intel"
    reports = "reports"
    mcp = "mcp"
    runtime = "runtime"
    logs = "logs"
    tasks = "tasks"
    workflow = "workflow"
    agents = "agents"
    capabilities = "capabilities"
    plugins = "plugins"
    marketplace = "marketplace"
    guards = "guards"
    architecture = "architecture"
    impact = "impact"
    repo_memory = "repo_memory"


class CommandEntry(BaseModel):
    name: str
    description: str
    category: str
    shortcut: str = ""
