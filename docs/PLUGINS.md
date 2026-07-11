# Plugins

## Overview

HYDRA supports declarative plugins that extend the capability catalog with new tools, adapters, and agents. Plugins are data-only — they are never executed directly.

## Plugin format

Plugins are YAML files with this structure:

```yaml
id: my-plugin
version: "1.0.0"
author: "Author Name"
description: "Plugin description"
enabled: true

capabilities:
  - id: my_capability
    category: web
    tools: [my_tool]
    finding_types: [xss, sqli]
    target_types: [url]

adapters:
  - capability: my_capability
    tool: my_tool
    execution_profile: safe_subprocess

agents:
  - id: my_agent
    responsibilities: ["web scanning"]
    capabilities: [my_capability]

dependencies:
  requires:
    - capability: port_scanning
      relation: requires
```

## Plugin directories

Plugins are loaded from:

1. `hydra/plugins/` — built-in plugins
2. `plugins/` — user plugins (project root)
3. Paths registered via `plugin_catalog`

## Registration

Plugins are registered declaratively and validated at load time:

```python
# Via MCP tool
plugin_catalog()        # List installed plugins
plugin_capabilities()   # What capabilities plugins add
plugin_coverage()       # Plugin ecosystem coverage
plugin_health()         # Plugin health metrics
```

## Trust model

- **Built-in** plugins are trusted by default
- **User** plugins are validated against the schema
- **External** plugins require explicit trust declaration

## Plugin capabilities

Plugins contribute to the effective capability catalog. The core catalog defines base capabilities; plugins extend it with additional tools and coverage.

```python
# See what a specific plugin adds
plugin_capabilities(plugin_id="my-plugin")

# Check ecosystem composition
plugin_summary()
```

## Writing a plugin

1. Create a YAML file following the schema above
2. Place it in `plugins/` or `hydra/plugins/`
3. Verify with `plugin_catalog()` — validation errors are reported
4. Check coverage with `plugin_coverage()`

See `hydra/plugins/sample_plugin.py` for an example.
