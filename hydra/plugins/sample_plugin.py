"""Sample plugin — demonstrates registering a command via the CapabilityRegistry.

Used by Phase 7 integration tests to verify the plugin→command→TUI pipeline.
"""

from hydra.plugins import HydraPlugin


class SamplePlugin(HydraPlugin):
    NAME = "sample_plugin"
    VERSION = "0.1.0"
    DESCRIPTION = "Sample plugin for integration testing"
    PLUGIN_TYPE = "tool"

    async def initialize(self, config):
        self._config = config

    async def execute(self, action, params):
        if action == "ping":
            return {"status": "pong", "message": "Sample plugin is alive"}
        return {"error": f"Unknown action: {action}"}

    def get_actions(self):
        return ["ping"]

    def register_commands(self, cmd_registry, cap_registry):
        """Register plugin commands with both registries."""
        from hydra.commands.registry import Command
        from hydra.commands.result import CommandResult
        from hydra.registry.capability import Capability, CapabilityType

        def _ping(args, kwargs, ctx):
            return CommandResult.success({
                "type": "plugin_result",
                "plugin": self.NAME,
                "result": {"status": "pong", "message": "Sample plugin is alive"},
            })

        cmd_registry.register(Command(
            name="ping",
            description="Ping the sample plugin",
            category="plugins",
            usage="/ping",
            handler=_ping,
        ))

        cap_registry.register(Capability(
            type=CapabilityType.COMMAND,
            id="ping",
            name="ping",
            description="Ping the sample plugin",
            source=f"plugin:{self.NAME}",
            metadata={"category": "plugins", "usage": "/ping"},
        ))

        cap_registry.register(Capability(
            type=CapabilityType.PLUGIN,
            id=f"plugin:{self.NAME}",
            name=self.NAME,
            description=self.DESCRIPTION,
            source=f"plugin:{self.NAME}",
            metadata={"version": self.VERSION, "actions": self.get_actions()},
        ))
