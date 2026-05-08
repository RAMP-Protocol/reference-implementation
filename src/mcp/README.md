# ramp-mcp-shim

FastMCP server exposing a single `ramp_fetch` tool to agentic harnesses. Forwards to the Broker's `/broker/v1/resolve` endpoint; holds no persistence.

## Install

```bash
cd src/mcp
uv sync
```

## Run

```bash
BROKER_URL=http://localhost:8082 uv run ramp-mcp
```

## Claude Code harness config

Add to `~/.claude/settings.json` under `mcpServers`:

```json
{
  "mcpServers": {
    "ramp": {
      "command": "uv",
      "args": ["--directory", "/path/to/src/mcp", "run", "ramp-mcp"],
      "env": { "BROKER_URL": "http://localhost:8082" }
    }
  }
}
```
