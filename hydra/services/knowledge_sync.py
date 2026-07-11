"""Knowledge Sync Service — cross-session knowledge synchronization (Phase 10.9)."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from hydra.services.base import BaseService
from hydra.services.event_bus import EventBus

SYNC_SOURCES = {"wiki", "memory", "graph", "ttp", "lessons", "findings", "patterns", "chains", "reports"}
CONFLICT_STRATEGIES = {"local_wins", "remote_wins", "merge", "manual"}
SYNC_STATES = {"pending", "syncing", "completed", "failed", "conflict"}


class KnowledgeSyncService(BaseService):

    def __init__(self, event_bus: EventBus, data_dir: Path | None = None):
        super().__init__(event_bus, data_dir)
        self._sync_log: list[dict] = []
        self._snapshots: dict[str, dict] = {}
        self._conflicts: list[dict] = []
        self._peers: dict[str, dict] = {}

    def create_snapshot(self, sources: list[str] | None = None) -> dict:
        selected = set(sources or SYNC_SOURCES)
        invalid = selected - SYNC_SOURCES
        if invalid:
            return {"status": "error", "message": f"Unknown sources: {invalid}"}

        snapshot_id = f"snap-{int(time.time() * 1000)}"
        items: dict[str, dict] = {}
        for src in sorted(selected):
            items[src] = {
                "source": src,
                "item_count": 0,
                "hash": hashlib.sha256(src.encode()).hexdigest()[:16],
            }

        snapshot = {
            "id": snapshot_id,
            "created_at": time.time(),
            "sources": sorted(selected),
            "items": items,
            "total_items": sum(v["item_count"] for v in items.values()),
        }
        self._snapshots[snapshot_id] = snapshot
        self._emit("knowledge_sync.snapshot_created", {"id": snapshot_id, "sources": sorted(selected)})
        return {"status": "created", "id": snapshot_id, **snapshot}

    def sync_to_peer(self, peer_id: str, snapshot_id: str = "") -> dict:
        if snapshot_id and snapshot_id not in self._snapshots:
            return {"status": "error", "message": f"Snapshot {snapshot_id} not found"}

        if not snapshot_id:
            snap = self.create_snapshot()
            snapshot_id = snap["id"]

        record = {
            "id": f"sync-{int(time.time() * 1000)}",
            "peer_id": peer_id,
            "snapshot_id": snapshot_id,
            "direction": "push",
            "state": "completed",
            "started_at": time.time(),
            "completed_at": time.time(),
            "items_synced": self._snapshots[snapshot_id]["total_items"],
            "conflicts": 0,
        }
        self._sync_log.append(record)
        self._peers.setdefault(peer_id, {"id": peer_id, "syncs": 0, "last_sync": 0})
        self._peers[peer_id]["syncs"] += 1
        self._peers[peer_id]["last_sync"] = time.time()
        self._emit("knowledge_sync.synced", {"peer_id": peer_id, "direction": "push"})
        return {"status": "synced", **record}

    def sync_from_peer(self, peer_id: str, data: dict | None = None) -> dict:
        incoming = data or {}
        record = {
            "id": f"sync-{int(time.time() * 1000)}",
            "peer_id": peer_id,
            "direction": "pull",
            "state": "completed",
            "started_at": time.time(),
            "completed_at": time.time(),
            "items_received": len(incoming),
            "conflicts": 0,
        }
        self._sync_log.append(record)
        self._peers.setdefault(peer_id, {"id": peer_id, "syncs": 0, "last_sync": 0})
        self._peers[peer_id]["syncs"] += 1
        self._peers[peer_id]["last_sync"] = time.time()
        self._emit("knowledge_sync.synced", {"peer_id": peer_id, "direction": "pull"})
        return {"status": "synced", **record}

    def detect_conflicts(self, local_items: list[dict], remote_items: list[dict]) -> dict:
        conflicts = []
        local_keys = {item.get("id", ""): item for item in local_items}
        for remote in remote_items:
            rid = remote.get("id", "")
            if rid in local_keys:
                local = local_keys[rid]
                if json.dumps(local, sort_keys=True) != json.dumps(remote, sort_keys=True):
                    conflict = {
                        "id": f"conflict-{len(self._conflicts)}",
                        "item_id": rid,
                        "local": local,
                        "remote": remote,
                        "state": "pending",
                    }
                    conflicts.append(conflict)
                    self._conflicts.append(conflict)
        return {"status": "detected", "conflict_count": len(conflicts), "conflicts": conflicts}

    def resolve_conflict(self, conflict_id: str, strategy: str = "local_wins") -> dict:
        if strategy not in CONFLICT_STRATEGIES:
            return {"status": "error", "message": f"Unknown strategy: {strategy}"}
        target = None
        for c in self._conflicts:
            if c["id"] == conflict_id:
                target = c
                break
        if not target:
            return {"status": "error", "message": f"Conflict {conflict_id} not found"}
        target["state"] = "resolved"
        target["strategy"] = strategy
        if strategy == "local_wins":
            target["result"] = target["local"]
        elif strategy == "remote_wins":
            target["result"] = target["remote"]
        else:
            target["result"] = {**target["local"], **target["remote"]}
        self._emit("knowledge_sync.conflict_resolved", {"conflict_id": conflict_id, "strategy": strategy})
        return {"status": "resolved", "conflict_id": conflict_id, "strategy": strategy}

    def list_peers(self) -> list[dict]:
        return list(self._peers.values())

    def get_sync_history(self, limit: int = 20) -> list[dict]:
        return self._sync_log[-limit:]

    def get_stats(self) -> dict:
        return {
            "total_syncs": len(self._sync_log),
            "total_snapshots": len(self._snapshots),
            "total_conflicts": len(self._conflicts),
            "resolved_conflicts": sum(1 for c in self._conflicts if c["state"] == "resolved"),
            "peers": len(self._peers),
            "by_direction": {
                "push": sum(1 for s in self._sync_log if s["direction"] == "push"),
                "pull": sum(1 for s in self._sync_log if s["direction"] == "pull"),
            },
        }
