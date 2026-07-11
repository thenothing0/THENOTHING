# Troubleshooting

## Common issues

### "Tool not found" errors

HYDRA wraps external security tools. If a tool is missing:

```bash
# Check which tools are available
python -m hydra --check-tools

# Auto-install Go-based tools
python -m hydra --install-tools
```

For system tools (nmap, whatweb), install via your package manager:

```bash
sudo apt install nmap whatweb  # Debian/Kali
```

### "not authorized" / scope gate blocks

HYDRA enforces deny-by-default authorization. Register your scope first:

```python
register_bounty_program(
    program="acme",
    platform="hackerone",
    in_scope="*.acme.com"
)
```

Or load from the program page:

```python
load_bounty_scope(url="https://hackerone.com/acme")
```

### MCP server won't start

1. Check Python version: `python --version` (need 3.10+)
2. Check dependencies: `pip install -r requirements.txt`
3. Check port availability (SSE mode): `lsof -i :8900`
4. Try verbose mode: `python mcp_server.py 2>&1 | head -50`

### Docker networking issues

If the MCP server inside Docker can't reach targets:

```bash
# Use host networking
docker run --network host hydra:mcp

# Or map specific ports
docker run -p 8900:8900 hydra:mcp
```

### Import errors

If you see `cannot import name 'get_config' from 'hydra.config'`:

```bash
# Reinstall in editable mode
pip install -e .
```

This error occurs when the `hydra/config/` package doesn't properly re-export symbols from `hydra/config.py`. The v1.0.0 release fixes this.

### API key issues

AI features require API keys:

```bash
export OPENAI_API_KEY="sk-..."
# or
export ANTHROPIC_API_KEY="sk-ant-..."
```

To run without AI:

```bash
python -m hydra -t example.com --no-ai
```

### Slow startup

HYDRA uses lazy imports to minimize startup time. If startup is slow:

1. Check that you're not importing unnecessary extras
2. Use `--no-ai` to skip AI provider initialization
3. Check disk I/O on the `data/` directory

### Test failures

```bash
# Run the full test suite
pytest tests/ -x -q

# Run only fast, offline tests (default)
pytest tests/

# Run integration tests (requires tools + HYDRA_RUN_INTEGRATION=1)
HYDRA_RUN_INTEGRATION=1 pytest -m integration
```

### Tor / proxy issues

If using Tor, ensure `LD_PRELOAD` is unset to avoid library conflicts:

```bash
unset LD_PRELOAD
```

## Getting help

- [GitHub Issues](https://github.com/thenothing-sec/hydra/issues)
- Check `docs/` for detailed documentation
- Run `python -m hydra --help` for CLI options
