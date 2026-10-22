# Falcon MCP testbench

Minimal read-only-by-default MCP server (stdio) for CrowdStrike Falcon.

## Setup
1. `uv sync`
2. `cp .env.example .env` and fill in your API client credentials (env only, never committed).
3. Smoke test: `uv run --env-file .env smoke_test.py`

## Required API scopes
- Hosts: Read
- Hosts: Write (only for `contain_host` / `lift_containment`)
- Alerts: Read

## Tools
`search_hosts`, `get_host_details`, `list_alerts`, `get_host_containment_status` (read-only, `limit` defaults to 10);
`contain_host`, `lift_containment` (refuse unless `ALLOW_WRITE=true` **and** `confirm=True`).

## Claude Code
```
claude mcp add falcon-testbench -e FALCON_CLIENT_ID=... -e FALCON_CLIENT_SECRET=... -e FALCON_BASE_URL=https://api.crowdstrike.com -e ALLOW_WRITE=false -- uv run --directory <path-to-this-dir> server.py
```

## Claude Desktop
Add to `claude_desktop_config.json` under `mcpServers`:
```json
"falcon-testbench": {"command": "uv", "args": ["run", "--directory", "<path-to-this-dir>", "server.py"],
  "env": {"FALCON_CLIENT_ID": "...", "FALCON_CLIENT_SECRET": "...", "ALLOW_WRITE": "false"}}
```
