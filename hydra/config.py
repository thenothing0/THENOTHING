"""
╔══════════════════════════════════════════════════════════════╗
║  THENOTHING Configuration — Central Configuration Registry       ║
║  Environment-driven, Docker-aware, production-grade         ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.config")

# ──────────────────────────────────────────────
#  Path Constants
# ──────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
RESULTS_DIR = BASE_DIR / "results"
REPORTS_DIR = BASE_DIR / "reports"
WORDLISTS_DIR = BASE_DIR / "wordlists"

for _d in [DATA_DIR, LOGS_DIR, RESULTS_DIR, REPORTS_DIR, WORDLISTS_DIR]:
    _d.mkdir(parents=True, exist_ok=True)


@dataclass
class RedisConfig:
    """Redis connection configuration (memory bus)."""
    host: str = os.getenv("REDIS_HOST", "127.0.0.1")
    port: int = int(os.getenv("REDIS_PORT", "6379"))
    password: str = os.getenv("REDIS_PASSWORD", "")
    db: int = int(os.getenv("REDIS_DB", "0"))
    
    @property
    def url(self) -> str:
        auth = f":{self.password}@" if self.password else ""
        return f"redis://{auth}{self.host}:{self.port}/{self.db}"


@dataclass
class PostgresConfig:
    """PostgreSQL connection configuration (persistent store)."""
    host: str = os.getenv("POSTGRES_HOST", "127.0.0.1")
    port: int = int(os.getenv("POSTGRES_PORT", "5432"))
    user: str = os.getenv("POSTGRES_USER", "hydra")
    password: str = os.getenv("POSTGRES_PASSWORD", "hydra_secret")
    database: str = os.getenv("POSTGRES_DB", "hydra")
    
    @property
    def dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"


@dataclass
class AIProviderConfig:
    """Configuration for an AI provider."""
    name: str
    enabled: bool = False
    api_key: str = ""
    base_url: str = ""
    model: str = ""
    timeout: int = 60
    max_retries: int = 3
    cost_per_1k_tokens: float = 0.0
    capabilities: list = field(default_factory=list)


@dataclass
class SwarmConfig:
    """Multi-agent swarm configuration."""
    max_concurrent_agents: int = int(os.getenv("SWARM_MAX_AGENTS", "10"))
    agent_timeout: int = int(os.getenv("SWARM_AGENT_TIMEOUT", "300"))
    retry_failed_tasks: bool = True
    max_task_retries: int = 3
    task_queue_size: int = 1000
    heartbeat_interval: int = 10
    coordinator_tick_interval: float = 0.5


@dataclass
class MCPConfig:
    """MCP Tool Execution Layer configuration."""
    host: str = os.getenv("MCP_HOST", "0.0.0.0")
    port: int = int(os.getenv("MCP_PORT", "8900"))
    tool_timeout: int = int(os.getenv("MCP_TOOL_TIMEOUT", "120"))
    max_concurrent_tools: int = int(os.getenv("MCP_MAX_CONCURRENT", "5"))
    sandbox_enabled: bool = True
    allowed_tools: list = field(default_factory=lambda: [
        "subfinder", "amass", "httpx", "nuclei", "ffuf",
        "dirsearch", "nmap", "whatweb", "wafw00f", "gau",
        "waybackurls", "katana", "gospider",
    ])


@dataclass
class LearningConfig:
    """Self-learning engine configuration."""
    enabled: bool = True
    reward_success: float = 1.0
    penalty_false_positive: float = -0.5
    penalty_missed: float = -0.3
    confidence_threshold: float = 0.70
    min_samples_to_learn: int = 5
    decay_factor: float = 0.95
    learning_rate: float = 0.01
    db_path: str = str(DATA_DIR / "learning.db")


@dataclass
class AttackGraphConfig:
    """Attack graph engine configuration."""
    max_depth: int = 10
    max_nodes: int = 10000
    prune_interval: int = 300
    persist_interval: int = 60


@dataclass
class CostConfig:
    """AI cost and token management configuration."""
    monthly_cap_usd: float = float(os.getenv("HYDRA_MONTHLY_CAP", "100.0"))
    daily_cap_usd: float = float(os.getenv("HYDRA_DAILY_CAP", "10.0"))
    per_scan_cap_usd: float = float(os.getenv("HYDRA_SCAN_CAP", "5.0"))
    warning_threshold: float = 0.8
    downgrade_threshold: float = 0.9


@dataclass
class SandboxConfig:
    """Security sandbox configuration."""
    enabled: bool = os.getenv("HYDRA_SANDBOX", "true").lower() == "true"
    max_requests_per_second: int = int(os.getenv("HYDRA_RATE_LIMIT", "50"))
    max_concurrent_tools: int = int(os.getenv("HYDRA_MAX_TOOLS", "5"))
    max_scan_duration: int = 7200
    allow_active_exploitation: bool = False


@dataclass
class DashboardConfig:
    """Real-time dashboard configuration."""
    enabled: bool = os.getenv("HYDRA_DASHBOARD", "true").lower() == "true"
    host: str = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    port: int = int(os.getenv("DASHBOARD_PORT", "8080"))


@dataclass
class ScopeConfig:
    """Bug bounty scope / program intelligence configuration."""
    platform: str = os.getenv("HYDRA_SCOPE_PLATFORM", "custom")
    program_id: str = os.getenv("HYDRA_PROGRAM_ID", "")
    enforce_scope: bool = os.getenv("HYDRA_ENFORCE_SCOPE", "true").lower() == "true"
    hackerone_token: str = os.getenv("HACKERONE_API_TOKEN", "")


@dataclass
class RecoveryConfig:
    """Workflow recovery configuration."""
    enabled: bool = True
    checkpoint_dir: str = str(DATA_DIR / "checkpoints")
    max_retries: int = 5
    checkpoint_interval: int = 60


@dataclass
class ConsensusConfig:
    """Multi-agent consensus configuration."""
    enabled: bool = os.getenv("HYDRA_CONSENSUS", "true").lower() == "true"
    quorum_size: int = 2
    approval_threshold: float = 0.6


@dataclass
class QueueConfig:
    """Distributed queue configuration."""
    mode: str = os.getenv("HYDRA_QUEUE_MODE", "local")  # local | distributed
    lease_seconds: int = 300
    dlq_max_size: int = 1000


@dataclass
class SemanticMemoryConfig:
    """Semantic memory / vector DB configuration."""
    enabled: bool = os.getenv("HYDRA_SEMANTIC_MEMORY", "true").lower() == "true"
    persist_dir: str = str(DATA_DIR / "chromadb")
    embedding_model: str = "all-MiniLM-L6-v2"


@dataclass
class PluginConfig:
    """Plugin system configuration."""
    enabled: bool = True
    plugin_dirs: str = str(BASE_DIR / "plugins")


@dataclass
class ObservabilityConfig:
    """Observability stack configuration."""
    metrics_enabled: bool = os.getenv("HYDRA_METRICS", "true").lower() == "true"
    tracing_enabled: bool = os.getenv("HYDRA_TRACING", "false").lower() == "true"


class HydraConfig:
    """Master configuration singleton."""
    
    _instance: Optional["HydraConfig"] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        self.redis = RedisConfig()
        self.postgres = PostgresConfig()
        self.swarm = SwarmConfig()
        self.mcp = MCPConfig()
        self.learning = LearningConfig()
        self.attack_graph = AttackGraphConfig()
        
        # New v2.0 subsystem configs
        self.cost = CostConfig()
        self.sandbox = SandboxConfig()
        self.dashboard = DashboardConfig()
        self.scope = ScopeConfig()
        self.recovery = RecoveryConfig()
        self.consensus = ConsensusConfig()
        self.queue = QueueConfig()
        self.semantic_memory = SemanticMemoryConfig()
        self.plugins = PluginConfig()
        self.observability = ObservabilityConfig()
        
        # AI Providers
        self.ai_providers = self._load_ai_providers()
        
        # Execution mode
        self.distributed = os.getenv("HYDRA_DISTRIBUTED", "false").lower() == "true"
        self.node_id = os.getenv("HYDRA_NODE_ID", "node-0")
        self.node_role = os.getenv("HYDRA_NODE_ROLE", "all")  # all | coordinator | worker
        
        # Security
        self.api_keys = {
            "shodan": os.getenv("SHODAN_API_KEY", ""),
            "virustotal": os.getenv("VT_API_KEY", ""),
            "securitytrails": os.getenv("ST_API_KEY", ""),
            "github": os.getenv("GITHUB_TOKEN", ""),
            "censys_id": os.getenv("CENSYS_ID", ""),
            "censys_secret": os.getenv("CENSYS_SECRET", ""),
        }
        
        logger.info(f"THENOTHING config loaded — node={self.node_id} distributed={self.distributed}")
    
    def _load_ai_providers(self) -> Dict[str, AIProviderConfig]:
        """Load all AI provider configurations from environment."""
        providers = {}
        
        # OpenAI
        openai_key = os.getenv("OPENAI_API_KEY", "")
        providers["openai"] = AIProviderConfig(
            name="openai",
            enabled=bool(openai_key),
            api_key=openai_key,
            base_url="https://api.openai.com/v1",
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            cost_per_1k_tokens=0.005,
            capabilities=["reasoning", "code_analysis", "report_generation", "vuln_classification"],
        )
        
        # Anthropic Claude
        claude_key = os.getenv("ANTHROPIC_API_KEY", "")
        providers["anthropic"] = AIProviderConfig(
            name="anthropic",
            enabled=bool(claude_key),
            api_key=claude_key,
            base_url="https://api.anthropic.com/v1",
            model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
            cost_per_1k_tokens=0.003,
            capabilities=["reasoning", "code_analysis", "exploit_analysis", "report_generation"],
        )
        
        # Ollama (Local)
        ollama_url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
        providers["ollama"] = AIProviderConfig(
            name="ollama",
            enabled=os.getenv("OLLAMA_ENABLED", "true").lower() == "true",
            base_url=ollama_url,
            model=os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
            cost_per_1k_tokens=0.0,
            capabilities=["reasoning", "code_analysis", "fast_classification"],
        )
        
        # Custom API
        custom_url = os.getenv("CUSTOM_LLM_URL", "")
        if custom_url:
            providers["custom"] = AIProviderConfig(
                name="custom",
                enabled=True,
                api_key=os.getenv("CUSTOM_LLM_KEY", ""),
                base_url=custom_url,
                model=os.getenv("CUSTOM_LLM_MODEL", "default"),
                capabilities=["reasoning"],
            )
        
        return providers
    
    def get_enabled_providers(self) -> Dict[str, AIProviderConfig]:
        """Return only enabled AI providers."""
        return {k: v for k, v in self.ai_providers.items() if v.enabled}
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize configuration for inspection."""
        return {
            "node_id": self.node_id,
            "distributed": self.distributed,
            "node_role": self.node_role,
            "ai_providers": {k: v.name for k, v in self.get_enabled_providers().items()},
            "redis": self.redis.url,
            "mcp_port": self.mcp.port,
        }


def get_config() -> HydraConfig:
    """Get the global configuration singleton."""
    return HydraConfig()
