# Skill: WebSocket Analysis

## Metadata
| **id** | `browser_websocket_analysis` |
| **version** | `1.0.0` |
| **output_root** | `output/<target>/evidence/browser/ws/` |

## Objective
Assess WebSocket auth (`Cookie`, `Authorization`, query token), `Origin` checks, subscription ACLs, and message schema validation.

## Trigger Conditions
`Upgrade: websocket`, `wss://` endpoints, real-time dashboards, chats.

## Technology Fingerprints
Socket.io, native WS, STOMP over WS, GraphQL subscriptions.

## Reasoning Heuristics
Cross-origin WS without creds; IDOR in subscription topics; replay of binary frames.

## Exploit Hypotheses
Unauth socket; cross-user room join; server-side message injection to clients.

## MCP Orchestration Logic
`httpx_probe` for upgrade paths; manual ws clients logged in `replay/ws_notes.md`.

## Stealth Guidance
Low message rate; avoid spamming broadcast channels.

## Validation Workflow
Second account subscription test; capture minimal frames redacted.

## Evidence Requirements
Handshake headers + message proof outline.

## Adaptive Branching
GraphQL subscriptions → `graphql/graphql_attack_surface.md`.

## Confidence Scoring
0.9 unauth access to private channel; misconfig only = lower.

## Replay Logic
Handshake curl / client script snippet.

## Reporting Guidance
Auth on connect, origin checks, per-channel authz, rate limits, message validation.
