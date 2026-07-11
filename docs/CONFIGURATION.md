# Configuration

HYDRA is configured via environment variables and configuration profiles. All settings have sensible defaults for offline operation.

## Environment variables

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `HYDRA_NODE_ID` | `hydra-001` | Node identifier in distributed mode |
| `HYDRA_NODE_ROLE` | `standalone` | Node role: `standalone`, `coordinator`, `worker` |
| `HYDRA_DISTRIBUTED` | `false` | Enable distributed mode |
| `HYDRA_ENFORCE_SCOPE` | `true` | Enforce scope checking (deny-by-default) |

### Rate limiting & budgets

| Variable | Default | Description |
|----------|---------|-------------|
| `HYDRA_RATE_LIMIT` | `5.0` | Max requests per second |
| `HYDRA_MAX_TOOLS` | `10` | Max concurrent tool executions |
| `HYDRA_SCAN_CAP` | `100` | Max scans per session |
| `HYDRA_DAILY_CAP` | `500` | Daily API call budget |
| `HYDRA_MONTHLY_CAP` | `10000` | Monthly API call budget |

### Scope & authorization

| Variable | Default | Description |
|----------|---------|-------------|
| `HYDRA_PROGRAM_ID` | _(empty)_ | Bug bounty program handle |
| `HYDRA_SCOPE_PLATFORM` | _(empty)_ | Platform: hackerone, bugcrowd, etc. |

### Features

| Variable | Default | Description |
|----------|---------|-------------|
| `HYDRA_SANDBOX` | `false` | Enable sandbox mode for tool execution |
| `HYDRA_DASHBOARD` | `false` | Enable web dashboard |
| `HYDRA_METRICS` | `true` | Enable metrics collection |
| `HYDRA_TRACING` | `false` | Enable distributed tracing |
| `HYDRA_CONSENSUS` | `false` | Enable consensus verification |
| `HYDRA_QUEUE_MODE` | `memory` | Queue backend: `memory` or `redis` |
| `HYDRA_SEMANTIC_MEMORY` | `false` | Enable vector/semantic memory |

### External services (optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | `127.0.0.1` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | _(empty)_ | Redis password |
| `POSTGRES_HOST` | `localhost` | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `OPENAI_API_KEY` | _(empty)_ | OpenAI API key (for AI features) |
| `ANTHROPIC_API_KEY` | _(empty)_ | Anthropic API key (for AI features) |

## Configuration profiles

HYDRA ships with predefined profiles in `hydra/config/manager.py`:

| Profile | Description |
|---------|-------------|
| `dev` | Development: verbose logging, relaxed limits |
| `test` | Testing: deterministic, no external services |
| `prod` | Production: strict limits, full observability |
| `offline` | Offline-only: no network, local tools only |
| `cloud` | Cloud: distributed mode, external services |

## Config file locations

1. `hydra/config.py` — dataclass-based configuration with env var binding
2. `hydra/config/manager.py` — profile-based ConfigManager
3. `hydra/config/secrets.py` — SecretStore for credential management
4. `.env` — environment variable overrides (loaded via python-dotenv)

## Offline-first design

HYDRA operates fully offline by default. No external services are required:

- All data stored locally under `data/`
- Wiki knowledge base at `wiki/`
- Learning stores at `data/*.db`
- No Redis/PostgreSQL needed in standalone mode
- AI features are optional (install `hydra-security[ai]`)
