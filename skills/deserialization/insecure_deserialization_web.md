# Skill: Insecure Deserialization (Web & API)

## Skill Metadata
| Field | Value |
|--------|--------|
| **id** | `insecure_deserialization_web` |
| **version** | `1.0.0` |
| **category** | Web / Object serialization |
| **correlates_with** | JWT `alg`, pickle, Java ViewState, .NET ViewState, PHP `unserialize` |

## Objective
Spot **trusted byte streams** deserialized into objects with **gadget chains**. Progress from **format detection** → **type confusion** → **safe signal** (error/gadget-specific) before any destructive payload—**ROE-gated** for RCE-class proofs.

## Scope Rules
- Many programs **prohibit** full RCE gadget chains—use **safe** canaries and **signal** proofs.
- Never deserialize **untrusted** attacker blobs into your own operator infra.

## Trigger Conditions
- Base64 blobs in cookies, body, hidden fields (`ViewState`, `javax.faces.ViewState`).
- `serialized`, `pickle`, `marshal`, `yaml.load`, Java serialized streams (`ac ed 00 05`).

## Technology Fingerprints
- Java: CommonsCollections gadgets (literature only unless ROE).
- PHP: `unserialize` on user data.
- Python: `pickle`, `PyYAML` unsafe load.
- .NET: BinaryFormatter patterns (legacy).

## Recon Methodology
1. Identify **who** deserializes **what** (framework defaults).
2. Format fingerprint magic bytes + endpoints that echo errors.
3. Map **type names** in exceptions for gadget research (offline).

## MCP Tool Orchestration Logic
- `httpx_probe` — cookies and headers size anomalies.
- `nuclei_scan` — deserialization signatures.
- `ffuf_fuzz` — parameter names suggesting serialized blobs.

**Branching:** If production + strict ROE → **report suspected** with format proof only.

## Reasoning Heuristics
- Error-based **class name** leaks are high-signal for Java/.NET.
- **Crypto** on ViewState without integrity still risky—separate hypothesis.

## Attack-Path Hypotheses
| ID | Hypothesis |
|----|----------------|
| H1 | Unsafe format detection |
| H2 | Type confusion leading to file read |
| H3 | RCE gadget (ROE) |
| H4 | JWT/JWE confusion adjacent to custom serialization |

## Validation Workflow
1. Safe format identification.
2. Benign malformed object to confirm parser path.
3. Escalate only with written approval.

## False-Positive Reduction
- Base64 that is JWT or protobuf ≠ Java serialization.

## Stealth + OPSEC Guidance
- Minimal payloads; avoid server thread exhaustion.

## Replay Procedures
- Store raw blob + endpoint + framework guess.

## Evidence Requirements
- Stack traces redacted; format proof; remediation: remove deserialization of user input, signed tokens, safe parsers.

## Reporting Methodology
- Clear separation: **confirmed** parser path vs **theoretical** gadgets.

## Confidence Scoring Logic
- Format + parser invocation: **0.75**; RCE proof: **1.0** (if allowed).

## Adaptive Branching Logic
- **Mobile/API** binary protocols → different fingerprint branch.

## Related Exploit Chains
- `skills/api/jwt_weaknesses.md`

## Safety Boundaries
No production RCE; follow coordinated disclosure for vendor issues.

## Output Artifact Requirements
`output/<target_slug>/deser/` — `format_notes.md`, `errors_redacted.log`
