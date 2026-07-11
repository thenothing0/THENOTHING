"""Builtin commands — registered at startup."""

from hydra.commands.builtins.system import register_system_commands
from hydra.commands.builtins.navigation import register_navigation_commands
from hydra.commands.builtins.security import register_security_commands
from hydra.commands.builtins.findings_cmds import register_findings_commands
from hydra.commands.builtins.knowledge import register_knowledge_commands
from hydra.commands.builtins.infrastructure import register_infrastructure_commands
from hydra.commands.builtins.intel import register_intel_commands
from hydra.commands.builtins.graph_cmds import register_graph_commands
from hydra.commands.builtins.agent_cmds import register_agent_commands
from hydra.commands.builtins.search_cmds import register_search_commands
from hydra.commands.builtins.learning_cmds import register_learning_commands
from hydra.commands.builtins.reasoning_cmds import register_reasoning_commands
from hydra.commands.builtins.collab_cmds import register_collab_commands
from hydra.commands.builtins.campaign_cmds import register_campaign_commands


def register_all_builtins(cmd_registry, capability_registry=None):
    """Register all builtin commands with both registries."""
    register_system_commands(cmd_registry)
    register_navigation_commands(cmd_registry)
    register_security_commands(cmd_registry)
    register_findings_commands(cmd_registry)
    register_knowledge_commands(cmd_registry)
    register_infrastructure_commands(cmd_registry)
    register_intel_commands(cmd_registry)
    register_graph_commands(cmd_registry)
    register_agent_commands(cmd_registry)
    register_search_commands(cmd_registry)
    register_learning_commands(cmd_registry)
    register_reasoning_commands(cmd_registry)
    register_collab_commands(cmd_registry)
    register_campaign_commands(cmd_registry)

    if capability_registry is not None:
        _sync_to_capabilities(cmd_registry, capability_registry)


def _sync_to_capabilities(cmd_registry, cap_registry):
    """Mirror CommandRegistry entries into CapabilityRegistry for discovery."""
    from hydra.registry.capability import Capability, CapabilityType

    for cmd in cmd_registry.list_commands(include_hidden=True):
        cap_registry.register(Capability(
            type=CapabilityType.COMMAND,
            id=cmd.name,
            name=cmd.name,
            description=cmd.description,
            source="builtin",
            metadata={"category": cmd.category, "usage": cmd.usage},
        ))
