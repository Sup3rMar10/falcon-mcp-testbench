# Falcon MCP testbench

Minimal read-only-by-default MCP server (stdio) for CrowdStrike Falcon.

## Setup
1. `uv sync`
2. `cp .env.example .env` and fill in your API client credentials (env only, never committed).
3. Smoke test: `uv run --env-file .env smoke_test.py [hosts alerts identity cloud workflows] [--write]`

`FALCON_MODULES` selects which modules are exposed (default: all). Writes need `ALLOW_WRITE=true` **and** `confirm=True`.
A 403 from any tool means the scope is missing or the module isn't licensed.

## Modules, tools, API scopes (W = write)
| Module | Tools | Scopes |
|---|---|---|
| hosts | search_hosts, get_host_details, get_host_containment_status, contain_host (W), lift_containment (W) | Hosts: Read; Hosts: Write (W tools only) |
| alerts | list_alerts | Alerts: Read |
| identity | identity_search_entities, identity_get_entity, identity_list_detections | Identity Protection Entities/Detections/Assessment/Timeline: Read; Identity Protection GraphQL: Write (required by the GraphQL endpoint, queries here are read-only) |
| cloud | cloud_list_accounts, cloud_search_assets, cloud_list_misconfigurations, cloud_list_image_vulns | CSPM registration: Read (accounts, unconfirmed); Cloud Security API Assets: Read; Cloud Security API Detections: Read; Falcon Container Image: Read |
| workflows | workflow_search_definitions, workflow_list_executions, workflow_get_execution, workflow_execute (W) | Workflows: Read; Workflows: Write (W tool only) |

## Claude Code
```
claude mcp add falcon-testbench -e FALCON_CLIENT_ID=... -e FALCON_CLIENT_SECRET=... -e ALLOW_WRITE=false -e FALCON_MODULES=hosts,alerts,identity,cloud,workflows -- uv run --directory <path-to-this-dir> server.py
```

## Claude Desktop
Add to `claude_desktop_config.json` under `mcpServers`:
```json
"falcon-testbench": {"command": "uv", "args": ["run", "--directory", "<path-to-this-dir>", "server.py"],
  "env": {"FALCON_CLIENT_ID": "...", "FALCON_CLIENT_SECRET": "...", "ALLOW_WRITE": "false"}}
```
