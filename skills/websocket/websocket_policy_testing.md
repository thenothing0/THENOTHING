# Skill: WebSocket Policy Testing

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `websocket_policy_testing` |
| **version** | `1.0.0` |
| **category** | Frontend / Realtime |
| **correlates_with** | CSWSH (cross-site WS hijacking), CORS, auth, injection over WS |

## Objective
Test WebSocket endpoints for **Cross-Site WebSocket Hijacking** (origin not validated on upgrade),
missing auth on the WS channel, and injection/authorization flaws in WS messages.

## Scope Rules
- Detection/PoC-only; benign messages; in-scope WS origins only.
- No flooding the channel.

## Trigger Conditions
- `upgrade_header`, `ws_wss`; `Upgrade: websocket`, `wss://` endpoints, SPA realtime features.

## Technology Fingerprints
- Socket.IO, SignalR, ws, STOMP, GraphQL subscriptions over WS.

## Recon Methodology
1. Capture the upgrade handshake; note auth (cookie/bearer/query token) and `Origin` handling.
2. Replay the handshake from a foreign `Origin` (CSWSH test).
3. Enumerate message types and authorization per message.

## MCP Tool Orchestration Logic
- `httpx_probe` — confirm the upgrade endpoint + handshake headers.
- `attack_web_probe cors` — reuse origin-reflection reasoning for the upgrade.
- Manual WS client for message replay (log to `output/`).

## Reasoning Heuristics
- Upgrade succeeds with an attacker `Origin` and cookie auth → CSWSH (cross-site read/write).
- Auth enforced only at handshake, not per message → message-level authz gaps.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|------------|
| H1 | CSWSH: foreign-origin upgrade with victim cookies |
| H2 | Missing per-message authorization (IDOR over WS) |
| H3 | Injection in a WS message reaching a backend sink |

## Validation Workflow
1. Demonstrate a foreign-origin handshake that authenticates → CSWSH PoC.
2. Show a cross-tenant message read/write; reverify.

## False-Positive Reduction
- An upgrade that requires a per-session token unguessable cross-site is not CSWSH.
- Public broadcast channels with no sensitive data are low/info.

## Stealth + OPSEC Guidance
- Keep message volume minimal; close sockets promptly.

## Replay Procedures
- Save the handshake request + the CSWSH PoC page + message transcript.

## Evidence Requirements
- The cross-origin handshake, a sensitive message read/write, remediation (validate Origin, per-message authz).

## Confidence Scoring Logic
- CSWSH with sensitive data: **0.9+**; origin-validation gap with no data: medium.

## Adaptive Branching Logic
- GraphQL-over-WS subscriptions → branch to `skills/graphql/graphql_attack_surface.md`.

## Related Exploit Chains
- `skills/cors/cors_exploitation.md`, `skills/api/bola_idor.md`

## Safety Boundaries
No channel flooding; benign messages; PoC depth only.

## Output Artifact Requirements
`output/<target_slug>/websocket/` — `handshake.txt`, `cswsh_poc.html`, `messages.log`
