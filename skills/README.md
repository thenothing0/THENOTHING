# THENOTHING modular skills (Claude Code)

This tree is the **data plane** for skills: each category folder contains `SKILL.yaml` consumed by `hydra.skills.yaml_loader` and merged into `build_full_library()`.

## Claude Code `.md` skills (methodology library)

Production methodology files live under nested paths, for example:

- `skills/xss/advanced_xss_hunting.md`
- `skills/api/graphql_introspection_abuse.md`
- `skills/cloud/aws_privilege_escalation.md`
- `skills/business_logic/race_condition.md`

Load in Claude Code with `@skills/...` or slash-command references. Each file is self-contained (metadata, MCP orchestration, validation, OPSEC, reporting).

## Layout

- `skills/<topic>/*.md` — Full operational playbooks (this library)  
- `skills/<category>/SKILL.yaml` — YAML metadata consumed by `hydra.skills.yaml_loader` and merged into `build_full_library()`  
- `skills/_schema.yaml` — Field reference for YAML authors  

## Authoring

1. For YAML: copy an existing `SKILL.yaml` and change `id`, `name`, `triggers`, `technologies`, `mcp_tools`, and `validation`.  
2. For Markdown: copy a peer `.md` file and preserve all sections (metadata through output artifacts).  
3. Keep **authorized testing** and **MCP-only execution** assumptions explicit.  
4. Run tests: `pytest tests/test_yaml_skills.py`

## Dynamic activation

At runtime, use `DynamicSkillActivator` with a `TechnologyFingerprint` so the planner (or Claude) ranks skills by stack overlap and attack-surface tags instead of running every playbook linearly.
