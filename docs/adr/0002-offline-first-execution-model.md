# ADR 0002 — Offline-first execution model

- **Status:** Accepted (Phase A)
- **Date:** 2026-06-02

## Context

Reconnaissance sources span local binaries (subfinder, amass) and many network services
(crt.sh, Chaos, SecurityTrails, Shodan, FOFA, GitHub, …). The platform must (a) model the full
source space for planning and learning, yet (b) run its entire test/CI suite — and day-to-day
operation — with **no network and no Kali tools**, deterministically. It must also never make a
network call the operator didn't intend.

## Decision

Execution is **policy-driven and offline-first** (`hydra/capabilities/sources.py`):

- `ExecutionPolicy` defaults to `mode="offline"`. A `Source` runs only if `runnable(policy)`
  permits it. Offline mode admits only `offline_capable` sources (local binary or cached
  fixtures). Network sources require `mode="online"` **and**, when `requires_api_key`, an
  available key in the policy.
- The **capability registry declares all sources regardless of machine state** (current + future),
  with metadata (`category`, `requires_network`, `requires_api_key`, `offline_capable`, trust +
  performance block). Declaring a source ≠ being able to run it.
- Source adapters resolve **cached evidence first** (`adapters/cached.py`), then a local-tool
  wrapper (`adapters/local_tools.py`); declared network sources without an adapter raise
  `SourceUnavailable` only when explicitly selected online.
- All fusion / scoring / promotion / memory logic is **pure** and runs offline against fixtures.

## Consequences

- CI is hermetic: green CI means real behavior, no flaky network.
- Adding a network source later (Phase E) is additive — declare metadata + write one adapter;
  no architectural change, no offline regression.
- The operator must opt into online mode explicitly (`recon_fuse(online=True)` +
  `HYDRA_SOURCE_KEYS`), making outbound traffic a conscious choice.
