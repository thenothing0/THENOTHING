"""Autonomous Campaign Service — campaign orchestration and management (Phase 10.11)."""

from __future__ import annotations

import time
from pathlib import Path

from hydra.services.base import BaseService
from hydra.services.event_bus import EventBus

CAMPAIGN_TYPES = {"bounty_hunt", "full_assessment", "api_audit", "cloud_audit", "quick_recon", "custom"}
CAMPAIGN_STATES = {"planning", "running", "paused", "completed", "failed", "cancelled"}
PHASE_NAMES = ["recon", "enumeration", "scanning", "exploitation", "validation", "reporting"]


class CampaignService(BaseService):

    def __init__(self, event_bus: EventBus, data_dir: Path | None = None):
        super().__init__(event_bus, data_dir)
        self._campaigns: dict[str, dict] = {}
        self._step_log: list[dict] = []

    def create_campaign(
        self,
        target: str,
        campaign_type: str = "bounty_hunt",
        scope: list[str] | None = None,
        config: dict | None = None,
    ) -> dict:
        if campaign_type not in CAMPAIGN_TYPES:
            return {"status": "error", "message": f"Unknown type: {campaign_type}. Valid: {CAMPAIGN_TYPES}"}

        campaign_id = f"campaign-{int(time.time() * 1000)}"
        campaign = {
            "id": campaign_id,
            "target": target,
            "type": campaign_type,
            "state": "planning",
            "scope": scope or [target],
            "config": config or {},
            "created_at": time.time(),
            "started_at": None,
            "completed_at": None,
            "current_phase": None,
            "phases_completed": [],
            "findings_count": 0,
            "steps_executed": 0,
        }
        self._campaigns[campaign_id] = campaign
        self._emit("campaign.created", {"id": campaign_id, "target": target, "type": campaign_type})
        return {"status": "created", **campaign}

    def start_campaign(self, campaign_id: str) -> dict:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"status": "error", "message": f"Campaign {campaign_id} not found"}
        if campaign["state"] not in ("planning", "paused"):
            return {"status": "error", "message": f"Cannot start campaign in state: {campaign['state']}"}

        campaign["state"] = "running"
        campaign["started_at"] = campaign["started_at"] or time.time()
        campaign["current_phase"] = PHASE_NAMES[0]
        self._emit("campaign.started", {"id": campaign_id})
        return {"status": "started", **campaign}

    def advance_phase(self, campaign_id: str) -> dict:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"status": "error", "message": f"Campaign {campaign_id} not found"}
        if campaign["state"] != "running":
            return {"status": "error", "message": f"Campaign not running (state={campaign['state']})"}

        current = campaign["current_phase"]
        if current:
            campaign["phases_completed"].append(current)

        current_idx = PHASE_NAMES.index(current) if current in PHASE_NAMES else -1
        if current_idx + 1 >= len(PHASE_NAMES):
            campaign["state"] = "completed"
            campaign["completed_at"] = time.time()
            campaign["current_phase"] = None
            self._emit("campaign.completed", {"id": campaign_id})
            return {"status": "completed", **campaign}

        next_phase = PHASE_NAMES[current_idx + 1]
        campaign["current_phase"] = next_phase
        self._emit("campaign.phase_advanced", {"id": campaign_id, "phase": next_phase})
        return {"status": "advanced", "phase": next_phase, **campaign}

    def record_step(self, campaign_id: str, action: str, result: dict | None = None) -> dict:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"status": "error", "message": f"Campaign {campaign_id} not found"}

        step = {
            "campaign_id": campaign_id,
            "phase": campaign.get("current_phase", "unknown"),
            "action": action,
            "result": result or {},
            "timestamp": time.time(),
        }
        self._step_log.append(step)
        campaign["steps_executed"] += 1
        self._emit("campaign.step_recorded", {"campaign_id": campaign_id, "action": action})
        return {"status": "recorded", **step}

    def record_finding(self, campaign_id: str, finding: dict) -> dict:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"status": "error", "message": f"Campaign {campaign_id} not found"}
        campaign["findings_count"] += 1
        self._emit("campaign.finding_recorded", {"campaign_id": campaign_id, "count": campaign["findings_count"]})
        return {"status": "recorded", "findings_count": campaign["findings_count"]}

    def pause_campaign(self, campaign_id: str) -> dict:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"status": "error", "message": f"Campaign {campaign_id} not found"}
        if campaign["state"] != "running":
            return {"status": "error", "message": "Can only pause a running campaign"}
        campaign["state"] = "paused"
        self._emit("campaign.paused", {"id": campaign_id})
        return {"status": "paused", **campaign}

    def cancel_campaign(self, campaign_id: str) -> dict:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"status": "error", "message": f"Campaign {campaign_id} not found"}
        if campaign["state"] in ("completed", "cancelled"):
            return {"status": "error", "message": f"Campaign already {campaign['state']}"}
        campaign["state"] = "cancelled"
        campaign["completed_at"] = time.time()
        self._emit("campaign.cancelled", {"id": campaign_id})
        return {"status": "cancelled", **campaign}

    def list_campaigns(self, state: str = "") -> list[dict]:
        campaigns = list(self._campaigns.values())
        if state:
            campaigns = [c for c in campaigns if c["state"] == state]
        return campaigns

    def get_campaign(self, campaign_id: str) -> dict:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"status": "error", "message": f"Campaign {campaign_id} not found"}
        steps = [s for s in self._step_log if s["campaign_id"] == campaign_id]
        return {**campaign, "steps": steps}

    def get_stats(self) -> dict:
        by_state: dict[str, int] = {}
        by_type: dict[str, int] = {}
        total_findings = 0
        for c in self._campaigns.values():
            by_state[c["state"]] = by_state.get(c["state"], 0) + 1
            by_type[c["type"]] = by_type.get(c["type"], 0) + 1
            total_findings += c["findings_count"]
        return {
            "total_campaigns": len(self._campaigns),
            "total_steps": len(self._step_log),
            "total_findings": total_findings,
            "by_state": by_state,
            "by_type": by_type,
        }
