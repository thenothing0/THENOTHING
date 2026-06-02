# Tasks

## Immediate (this week)
- [ ] **Send VK R2 reply** to Solimonka acknowledging fix + attach error-page screenshot with DevTools
- [ ] **Screenshot SMS** on +201286439183 for R6 proof archive
- [ ] **Wait on VK R6** — vendor reviewing. Do NOT contact proactively

## If VK R6 responds
- [ ] If **accepted** → collect bounty
- [ ] If **downgraded/informative** → send `REPORT_6_IMPACT_ESCALATION.md` with video proof + honest CAPTCHA correction
- [ ] If **more info needed** → respond within 24h with terminal recording + phone SMS screenshot

## Next campaigns
- [ ] **Start Ozon recon** — scoped at `output/ozon_scan/scope.txt`. ₽21M total paid, high potential. Run passive recon first
- [ ] **Check Tripadvisor status** on Bugcrowd — 20 reports written, verify which were submitted and their triage status
- [ ] **Evaluate Tesla** — passive recon yielded nothing. Decide: invest deeper or deprioritize

## Backlog
- [ ] Tripadvisor APK dynamic testing — static findings (dev servers, debug panel, GraphQL map) need dynamic validation to chain to higher severity
- [ ] VK authenticated testing — if R6 bounty lands, reinvest into deeper VK testing with auth tokens
- [ ] Wiki maintenance — run `wiki/` lint, update with VK/Tripadvisor lessons learned

## Recently Completed (2026-06-01)
- [x] VK R1 re-validated — confirmed rejection correct (identical to public API)
- [x] VK R2 re-validated — confirmed VK patched redirect_uri reflection
- [x] VK R6 re-validated — still live, SMS sent to Egyptian number, CAPTCHA behavior documented
- [x] VK R6 impact escalation drafted
- [x] VK R2 reply to Solimonka drafted
- [x] Memory updated with all triage outcomes
- [x] Proof requirement feedback saved (all platforms, not just VK)
- [x] Project-wide context.md created
