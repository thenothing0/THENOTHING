# Project Overview
**THENOTHING v7.1** — Bug bounty research platform on Kali Linux. Claude Code + hydra-security MCP (22 tools). Operator: Egyptian researcher on Bugcrowd + Standoff 365.

# Architecture
```
newpro/
├── hydra/           # Core engine (22 subsystems)
├── mcp_server.py    # MCP tool server
├── skills/          # YAML skill definitions
├── commands/        # Slash commands (recon, hunt, chain, report)
├── wiki/            # BB knowledge base (see wiki/SCHEMA.md)
├── output/          # Per-target results
│   ├── vk_scan/     # VK: 7 reports, 5 submitted
│   ├── tripadvisor/ # TA: 20 reports + APK analysis
│   ├── apk_scan/    # TA APK static analysis
│   ├── tesla/       # Passive recon only
│   └── ozon_scan/   # Scoped, not started
├── context.md       # This file
├── decisions.md     # Technical decisions & lessons
├── tasks.md         # Task tracking
└── CLAUDE.md        # System instructions
```

# Target Status

| Target | Platform | State | Key Item |
|--------|----------|-------|----------|
| VK | Standoff 365 | **R6 in vendor review** | SMS abuse — only live report. Others closed/fixed. |
| Tripadvisor | Bugcrowd | 20 reports written | Check submission status. APK needs dynamic testing. |
| Tesla | Bugcrowd | Passive recon | No findings. Low priority. |
| Ozon | Standoff 365 | Scoped only | ₽21M paid, high potential. Ready to start. |

## VK Detail
- R1: Rejected (correct). R2: Fixed by VK. R3, R7: Informative. R4, R5: Not submitted.
- **R6 (auth.validatePhone)**: unauthenticated SMS send, still live 2026-06-01. CAPTCHA after ~2 req/phone/IP. Mass-targeting bypasses CAPTCHA. Impact escalation drafted.
- Triager: Solimonka. Reply for R2 drafted at `output/vk_scan/REPORT_2_REPLY_TO_VK.md`.

# References
- Decisions & lessons → `decisions.md`
- Task tracking → `tasks.md`
- Memory system → `.claude/projects/-home-thenothing-Desktop-newpro/memory/MEMORY.md`
- VK scope → `output/vk_scan/scope.txt`
- TA scope → `scope.txt`
- Ozon scope → `output/ozon_scan/scope.txt`

# Next Session Startup
Read `context.md` → `decisions.md` → `tasks.md`. Key state: VK R6 in vendor review (wait), R2 reply needs sending, Ozon ready to start. Always attach proof with reports. Full instructions in `CLAUDE.md`.
