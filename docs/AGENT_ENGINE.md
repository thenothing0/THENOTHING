# HYDRA v2.1 — Autonomous AI Agent Engine

An **additive** planning layer above the existing HYDRA backend. The agent decides
*which existing HYDRA commands to run* to achieve a natural-language objective, and
executes them **only** through `HydraFacade.execute_command()`. It never bypasses
HYDRA, changes its architecture, or adds third-party dependencies (stdlib + Textual +
Rich only).

## Guarantees

- **Backend frozen.** No public API, service, command, workflow, EventBus or plugin
  changes. The only backend touch is one additive `ServiceContainer.agent_engine`
  property (distinct from the existing swarm `.agents` service).
- **Execution boundary.** The `Executor` calls a single injected `execute_command`
  callable — never a service directly. In the TUI the callable is a thin adapter that
  runs `facade.execute_command(cmd)` and resolves the async `pending` recon/scan/campaign
  dispatches exactly as the manual UI already does.
- **No mock data.** The reasoner summarises only real command outputs; when the backend
  supplies no progress/confidence, the UI degrades to spinner/elapsed/status.
- **Offline-first, terminal-first.** Rule-based planning (no LLM/network). The only UI is
  `python -m control_center`.

## Package layout (`hydra/agent/`)

| Module | Responsibility |
|--------|----------------|
| `models.py` | Enums + serialisable dataclasses (`Task`, `Goal`, `ExecutionPlan`, `Reflection`, …) |
| `prompts.py` | Offline intent→command tables, target/vuln extraction |
| `planner.py` | `Planner` — objective → ordered `ExecutionPlan` of real commands; dynamic replan. Never executes |
| `scheduler.py` | `Scheduler` — dependency-driven readiness; event-driven, no polling |
| `executor.py` | `Executor` — runs tasks via the injected callable; retry/timeout/cancel/parallel |
| `memory.py` | Working / Conversation / Execution / Knowledge memory (bounded, persisted, resumable) |
| `context.py` | `ContextBuilder` — read-only context from KG/scope/findings/reports/tools/recents |
| `reasoner.py` | `Reasoner` — grounded Observe→Think→Plan→Execute→Observe→Reflect trace |
| `reflection.py` | `ReflectionEngine` — success/failure/missing/unexpected → RETRY/ALTERNATIVE/CONTINUE/ABORT |
| `goals.py` | `GoalTracker` — completion %, current/blocked tasks, confidence |
| `state.py` | `AgentStateMachine` — thread-safe, observable lifecycle |
| `session.py` | `AgentSession` — serialisable run state (plan + memory + trace) for resume |
| `orchestrator.py` | `Orchestrator` — the single public interface coordinating everything |
| `service.py` | `AgentService(BaseService)` — registered as `ServiceContainer.agent_engine` |

## Reasoning loop

```
PLANNING → EXECUTING → (per task) EXECUTING → REFLECTING → [PLANNING replan] → EXECUTING …
        → COMPLETED / FAILED / CANCELLED
```

Bounded by `max_iterations` (default 200); reflection owns cross-iteration retries via
replanning, the executor does at most `max_retries` attempts per call.

## Usage

Programmatic:

```python
from hydra.services import ServiceContainer
container = ServiceContainer()
session = container.agent_engine.run("assess example.com", facade.execute_command, facade=facade)
print(session.status, session.plan.revision)
```

Terminal (chat-first):

```
/agent assess example.com
```

The plan tree, reasoning stream, task updates, goal progress and confidence appear
naturally inside the conversation; the right context drawer shows the live goal snapshot.

## Events (all additive, `agent.*`)

`agent.started`, `agent.plan.created`, `agent.plan.updated`, `agent.state`,
`agent.task.started|completed|failed|ready|cancelled`, `agent.reasoning`,
`agent.reflection`, `agent.goal.progress`, `agent.completed`, `agent.cancelled`,
`agent.resumed`, `agent.session.started|finished`.

## Telemetry

Timers `agent.planning|execution|reasoning|reflection`; counters `agent.commands`,
`agent.task.success|failure`. Read via `hydra.observability.telemetry`.

## Persistence & resume

Each run persists memory (`data/agent/<id>.json`) and the full session
(`data/agent/sessions/<id>.json`). After a restart, `AgentService.resume(session_id, …)`
reloads and continues remaining tasks without replanning.

## Tests

`tests/test_agent_batch1..8b*.py` — 258 tests across planning, execution, memory/context,
reasoning/reflection, orchestration, events/telemetry, Textual integration, thread-safety,
resume and cancellation.
