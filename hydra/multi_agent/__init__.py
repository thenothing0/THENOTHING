"""HYDRA v2.2 — Multi-Agent Collaboration Engine.

An additive layer that turns the single autonomous agent into a coordinated team
of specialists (planner, recon, web, network, knowledge, report) under a
coordinator. It never changes the HYDRA backend, adds no third-party
dependencies, and executes ONLY through ``HydraFacade.execute_command()``.

Public surface is built up across implementation batches; import submodules
directly to avoid import-time coupling between batches.
"""

from __future__ import annotations

from hydra.multi_agent.models import (
    AgentInfo,
    AgentRole,
    AgentStatus,
    AgentTask,
    Campaign,
    CampaignStatus,
    Finding,
    Message,
    MessageType,
    MTaskState,
)
from hydra.multi_agent.shared_memory import SharedMemory
from hydra.multi_agent.task_queue import TaskQueue

__all__ = [
    "AgentInfo",
    "AgentRole",
    "AgentStatus",
    "AgentTask",
    "Campaign",
    "CampaignStatus",
    "Finding",
    "Message",
    "MessageType",
    "MTaskState",
    "SharedMemory",
    "TaskQueue",
]
