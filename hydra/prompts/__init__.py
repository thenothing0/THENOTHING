"""
╔══════════════════════════════════════════════════════════════╗
║  Prompt Engine — Master System Prompt Loader & Injector      ║
║  Loads the v7 master prompt and injects it into all AI       ║
║  interactions, cognitive loops, and agent reasoning calls     ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.prompts")

# ── Locate master prompt ──────────────────────

_PROMPTS_DIR = Path(__file__).parent
_MASTER_PROMPT_PATH = _PROMPTS_DIR / "master_system_prompt.md"


def load_master_prompt() -> str:
    """Load the master system prompt from disk."""
    if _MASTER_PROMPT_PATH.exists():
        return _MASTER_PROMPT_PATH.read_text(encoding="utf-8")
    logger.warning("Master prompt not found — using inline fallback")
    return _FALLBACK_PROMPT


def build_cognitive_prompt(
    target: str = "",
    phase: str = "",
    profile: str = "balanced",
    observations: List[str] = None,
    beliefs: List[str] = None,
    theories: List[str] = None,
    stealth_mode: str = "normal",
    context: Dict[str, Any] = None,
) -> str:
    """
    Build a full cognitive reasoning prompt for an AI call.

    Combines:
      1. Master system prompt (identity + rules)
      2. Current context (target, phase, profile)
      3. Cognitive state (observations, beliefs, theories)
      4. Phase-specific instructions
    """
    master = load_master_prompt()

    sections = [master, "\n---\n# CURRENT OPERATION CONTEXT\n"]

    if target:
        sections.append(f"**Target**: `{target}`")
    if phase:
        sections.append(f"**Cognitive Phase**: `{phase}`")
    if profile:
        sections.append(f"**Active Researcher Profile**: `{profile}`")
    if stealth_mode:
        sections.append(f"**Stealth Mode**: `{stealth_mode}`")

    if observations:
        sections.append("\n## Current Observations")
        for obs in observations[:20]:
            sections.append(f"- {obs}")

    if beliefs:
        sections.append("\n## Current Beliefs")
        for belief in beliefs[:10]:
            sections.append(f"- {belief}")

    if theories:
        sections.append("\n## Active Theories")
        for theory in theories[:10]:
            sections.append(f"- {theory}")

    # Phase-specific instructions
    phase_instructions = _PHASE_INSTRUCTIONS.get(phase, "")
    if phase_instructions:
        sections.append(f"\n## Phase Instructions\n{phase_instructions}")

    if context:
        sections.append("\n## Additional Context")
        for k, v in context.items():
            sections.append(f"- **{k}**: {v}")

    return "\n".join(sections)


def build_debate_prompt(
    role: str,
    finding: Dict[str, Any],
    previous_arguments: List[str] = None,
) -> str:
    """Build a debate agent prompt for adversarial reasoning."""
    master = load_master_prompt()

    role_instructions = {
        "hypothesis": (
            "You are the HYPOTHESIS AGENT. Your role is to:\n"
            "- Analyze the finding and argue FOR its validity\n"
            "- Evaluate evidence strength and exploit plausibility\n"
            "- Provide a confidence score (0-100) with reasoning\n"
            "- Identify what additional evidence would strengthen the case"
        ),
        "skeptic": (
            "You are the SKEPTIC AGENT. Your role is to:\n"
            "- Challenge every assumption in the finding\n"
            "- Detect hallucination indicators (vague language, unsupported claims)\n"
            "- Find contradictions in the evidence\n"
            "- Identify missing evidence that should exist if the finding is real\n"
            "- Provide a rejection confidence (0-100)"
        ),
        "opsec": (
            "You are the OPSEC ANALYST. Your role is to:\n"
            "- Evaluate the stealth risk of testing this finding\n"
            "- Estimate detection probability by WAF/IDS/SOC\n"
            "- Recommend stealth approach if proceeding\n"
            "- Flag any actions that might burn the operation"
        ),
        "referee": (
            "You are the REFEREE. Your role is to:\n"
            "- Weigh all arguments from Hunter, Skeptic, and OPSEC\n"
            "- Render a final verdict: ACCEPT, REJECT, or NEEDS_MORE_EVIDENCE\n"
            "- Provide final confidence score (0-100)\n"
            "- Justify the decision with clear reasoning"
        ),
    }

    sections = [
        master,
        f"\n---\n# DEBATE ROLE: {role.upper()}\n",
        role_instructions.get(role, ""),
        f"\n## Finding Under Review\n```json\n{_safe_json(finding)}\n```",
    ]

    if previous_arguments:
        sections.append("\n## Previous Arguments")
        for arg in previous_arguments:
            sections.append(f"- {arg}")

    sections.append(
        "\n## Your Response Format\n"
        "Provide:\n"
        "1. **Position**: support / challenge / neutral\n"
        "2. **Claim**: Your main argument (1-2 sentences)\n"
        "3. **Evidence**: What supports your position\n"
        "4. **Weaknesses**: Issues you identified\n"
        "5. **Confidence**: 0-100 score\n"
        "6. **Reasoning**: Detailed chain-of-thought"
    )

    return "\n".join(sections)


def build_bounty_hunt_prompt(
    programs: List[Dict[str, Any]],
    strengths: List[str] = None,
) -> str:
    """Build a prompt for autonomous target selection reasoning."""
    master = load_master_prompt()

    sections = [
        master,
        "\n---\n# TARGET SELECTION MODE\n",
        "You are in AUTONOMOUS BOUNTY HUNTING mode.",
        "Analyze the following programs and select the best targets.\n",
        "## Available Programs\n",
    ]

    for i, prog in enumerate(programs[:20]):
        sections.append(
            f"{i+1}. **{prog.get('name', 'Unknown')}** — "
            f"Max bounty: ${prog.get('max_bounty', 0):,.0f}, "
            f"Scope: {prog.get('scope_size', '?')} assets, "
            f"Competition: {prog.get('competition', '?')}, "
            f"Tech: {', '.join(prog.get('tech_stack', []))}"
        )

    if strengths:
        sections.append(f"\n## Our Strengths\n{', '.join(strengths)}")

    sections.append(
        "\n## Your Task\n"
        "1. Score each program (0-100)\n"
        "2. Select top 3 targets with reasoning\n"
        "3. Recommend a researcher profile for each\n"
        "4. Identify the most promising attack vectors per target"
    )

    return "\n".join(sections)


# ── Phase-specific instruction templates ──────

_PHASE_INSTRUCTIONS = {
    "observe": (
        "You are in the OBSERVE phase. Focus on:\n"
        "- Gathering raw signals about the target\n"
        "- Identifying assets, endpoints, technologies\n"
        "- Noting behavioral patterns and anomalies\n"
        "- DO NOT attempt exploitation yet\n"
        "- Record everything as structured observations"
    ),
    "understand": (
        "You are in the UNDERSTAND phase. Focus on:\n"
        "- Correlating observations into beliefs\n"
        "- Identifying trust boundaries and auth flows\n"
        "- Building a mental model of the architecture\n"
        "- Inferring hidden dependencies and logic"
    ),
    "reason": (
        "You are in the REASON phase. Focus on:\n"
        "- Generating exploit theories from beliefs\n"
        "- Identifying attack vectors with highest success probability\n"
        "- Considering chained exploit paths\n"
        "- Estimating feasibility and impact per theory"
    ),
    "simulate": (
        "You are in the SIMULATE phase. This is CRITICAL:\n"
        "- Predict what will happen if each theory is tested\n"
        "- Estimate detection probability (0-100%)\n"
        "- Model defensive reactions (WAF, IDS, rate limiting)\n"
        "- Calculate blast radius\n"
        "- If risk > 70%, recommend NOT proceeding"
    ),
    "execute": (
        "You are in the EXECUTE phase:\n"
        "- Only execute theories that passed simulation\n"
        "- Use stealth-appropriate tooling\n"
        "- Record all evidence\n"
        "- Monitor for blocking indicators\n"
        "- Abort if detection signals appear"
    ),
    "validate": (
        "You are in the VALIDATE phase:\n"
        "- Run adversarial debate on each finding\n"
        "- Verify evidence quality\n"
        "- Check for hallucination indicators\n"
        "- Confirm reproducibility\n"
        "- Reject findings that lack strong evidence"
    ),
    "learn": (
        "You are in the LEARN phase:\n"
        "- Record all outcomes (success and failure)\n"
        "- Extract new heuristics\n"
        "- Update skill confidence scores\n"
        "- Identify detection triggers to avoid\n"
        "- Evolve methodology for next cycle"
    ),
}


def _safe_json(data: Any) -> str:
    """Safe JSON serialization."""
    import json
    try:
        return json.dumps(data, indent=2, default=str)
    except Exception:
        return str(data)


# ── Fallback prompt (if file missing) ─────────

_FALLBACK_PROMPT = """# THENOTHING v7 — Autonomous Cognitive Red Team

You are an autonomous cognitive offensive security research system.
You MUST: observe → understand → reason → simulate → debate → execute → learn.
You MUST simulate before executing. You MUST debate before accepting findings.
You MUST respect scope boundaries. You MUST explain every decision.
"""
