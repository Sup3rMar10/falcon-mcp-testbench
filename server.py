import json
import os
import sys

from falconpy import (
    Alerts,
    CloudSecurityAssets,
    CloudSecurityDetections,
    ContainerVulnerabilities,
    CSPMRegistration,
    Hosts,
    IdentityProtection,
    Workflows,
)
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("falcon-testbench")
MODULES = {m.strip() for m in os.environ.get("FALCON_MODULES", "hosts,alerts,identity,cloud,workflows").split(",")}
_services = {}


def tool(module):
    """Register as an MCP tool only if the module is enabled; the function stays callable either way."""
    return mcp.tool() if module in MODULES else (lambda f: f)


def _out(data):
    return json.dumps(data, separators=(",", ":"), default=str)


def _err(message, status_code=None):
    return _out({"status_code": status_code, "message": message})


def _api_error(resp):
    """Return a JSON error string if the FalconPy response failed, else None."""
    code = resp.get("status_code")
    if code and 200 <= code < 300:
        return None
    body = resp.get("body")
    errors = (body.get("errors") if isinstance(body, dict) else None) or []
    msg = "; ".join(e.get("message", "") for e in errors) or "request failed"
    if code == 403:
        msg += " (not licensed or scope missing)"
    return _err(msg, code)


def _call(service, method, **kwargs):
    """Call a FalconPy method. Returns (body, error_json); never raises."""
    cid, secret = os.environ.get("FALCON_CLIENT_ID"), os.environ.get("FALCON_CLIENT_SECRET")
    if not cid or not secret:
        return None, _err("FALCON_CLIENT_ID / FALCON_CLIENT_SECRET not set", 401)
    try:
        if service not in _services:
            base = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com")
            _services[service] = service(client_id=cid, client_secret=secret, base_url=base)
        r = getattr(_services[service], method)(**kwargs)
    except Exception as e:  # keep tool output free of stack traces
        return None, _err(f"{type(e).__name__}: {e}")
    return r.get("body"), _api_error(r)


def _fql(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _clamp(limit):
    return max(1, min(limit, 100))


def _pick(record, keys):
    return {k: record[k] for k in keys if record.get(k) is not None}


def _query_then_get(service, query_method, get_method, id_kw, limit, **query_kwargs):
    """Two-step FalconPy lookup: query IDs, then fetch records. Returns (records, error_json)."""
    body, err = _call(service, query_method, limit=_clamp(limit), **query_kwargs)
    if err:
        return None, err
    ids = body.get("resources", [])
    if not ids:
        return [], None
    body, err = _call(service, get_method, **{id_kw: ids})
    return (None, err) if err else (body.get("resources", []), None)


# ---------------------------------------------------------------- hosts

@tool("hosts")
def search_hosts(hostname: str | None = None, status: str | None = None, limit: int = 10) -> str:
    """Search hosts by hostname (substring) and/or status (normal, contained, containment_pending, lift_containment_pending)."""
    parts = []
    if hostname:
        parts.append(f"hostname:*'*{_fql(hostname)}*'")
    if status:
        parts.append(f"status:'{_fql(status)}'")
    hosts, err = _query_then_get(Hosts, "query_devices_by_filter", "get_device_details", "ids", limit, filter="+".join(parts))
    if err:
        return err
    keys = ["device_id", "hostname", "platform_name", "status", "last_seen", "agent_version"]
    return _out([{("platform" if k == "platform_name" else k): h.get(k) for k in keys} for h in hosts])


@tool("hosts")
def get_host_details(device_id: str) -> str:
    """Get the full Falcon record for one host."""
    body, err = _call(Hosts, "get_device_details", ids=[device_id])
    if err:
        return err
    hosts = body.get("resources", [])
    return _out(hosts[0]) if hosts else _err("host not found", 404)


@tool("hosts")
def get_host_containment_status(device_id: str) -> str:
    """Get the containment status of a host (normal, contained, containment_pending, lift_containment_pending)."""
    body, err = _call(Hosts, "get_device_details", ids=[device_id])
    if err:
        return err
    hosts = body.get("resources", [])
    if not hosts:
        return _err("host not found", 404)
    status = hosts[0].get("status")
    return _out({"device_id": device_id, "status": status, "contained": status == "contained"})


def _write_guard(confirm):
    """Return an error JSON string unless writes are enabled and confirmed, else None."""
    if os.environ.get("ALLOW_WRITE", "false").lower() != "true":
        return _err("write actions disabled: set ALLOW_WRITE=true", 403)
    if confirm is not True:
        return _err("confirm=True is required", 400)
    return None


def _host_action(action, device_id, confirm):
    if err := _write_guard(confirm):
        return err
    body, err = _call(Hosts, "perform_action", action_name=action, ids=[device_id])
    if err:
        return err
    return _out({"device_id": device_id, "action": action, "result": body.get("resources")})


@tool("hosts")
def contain_host(device_id: str, confirm: bool = False) -> str:
    """WRITE: network-contain a host. Requires ALLOW_WRITE=true and confirm=True."""
    return _host_action("contain", device_id, confirm)


@tool("hosts")
def lift_containment(device_id: str, confirm: bool = False) -> str:
    """WRITE: lift network containment on a host. Requires ALLOW_WRITE=true and confirm=True."""
    return _host_action("lift_containment", device_id, confirm)


# --------------------------------------------------------------- alerts

@tool("alerts")
def list_alerts(severity: str | None = None, limit: int = 10) -> str:
    """List recent alerts, newest first. severity: Informational, Low, Medium, High, Critical."""
    fql = f"severity_name:'{_fql(severity.title())}'" if severity else ""
    alerts, err = _query_then_get(
        Alerts, "query_alerts_v2", "get_alerts_v2", "composite_ids", limit, filter=fql, sort="created_timestamp.desc"
    )
    if err:
        return err
    return _out([
        {
            "id": a.get("composite_id"),
            "severity": a.get("severity_name"),
            "name": a.get("display_name") or a.get("name"),
            "status": a.get("status"),
            "created": a.get("created_timestamp"),
            "hostname": (a.get("device") or {}).get("hostname"),
        }
        for a in alerts
    ])


# ------------------------------------------------------------- identity

_ENTITY_FIELDS = "entityId type primaryDisplayName secondaryDisplayName riskScore riskScoreSeverity riskFactors { type severity }"


def _graphql(query):
    """Run an Identity Protection GraphQL query. Returns (data, error_json)."""
    body, err = _call(IdentityProtection, "graphql", query=query)
    if err:
        return None, err
    if body.get("errors"):  # GraphQL reports query errors with HTTP 200
        return None, _err("; ".join(e.get("message", "") for e in body["errors"]), 400)
    return body.get("data") or {}, None


def _entity(node):
    return {
        "id": node.get("entityId"),
        "type": node.get("type"),
        "name": node.get("primaryDisplayName"),
        "secondary_name": node.get("secondaryDisplayName"),
        "risk_score": node.get("riskScore"),
        "risk_severity": node.get("riskScoreSeverity"),
        "risk_factors": [f"{f.get('type')}:{f.get('severity')}" for f in node.get("riskFactors") or []],
    }


@tool("identity")
def identity_search_entities(name_or_email: str, limit: int = 10) -> str:
    """Find identity entities (users/endpoints) by name pattern or email; returns id, name, risk score, risk factors."""
    if "@" in name_or_email:
        match = f"types: [USER], secondaryDisplayNamePattern: {json.dumps(name_or_email)}"
    else:
        match = f"primaryDisplayNamePattern: {json.dumps(name_or_email)}"
    data, err = _graphql(f"{{ entities(first: {_clamp(limit)}, {match}) {{ nodes {{ {_ENTITY_FIELDS} }} }} }}")
    if err:
        return err
    return _out([_entity(n) for n in data.get("entities", {}).get("nodes", [])])


@tool("identity")
def identity_get_entity(entity_id: str) -> str:
    """Get one identity entity with risk factors and open incidents."""
    q = (
        f"{{ entities(first: 1, entityIds: [{json.dumps(entity_id)}]) {{ nodes {{ {_ENTITY_FIELDS} "
        "openIncidents(first: 10) { nodes { type startTime endTime } } } } } }"
    )
    data, err = _graphql(q)
    if err:
        return err
    nodes = data.get("entities", {}).get("nodes", [])
    if not nodes:
        return _err("entity not found", 404)
    incidents = (nodes[0].get("openIncidents") or {}).get("nodes", [])
    return _out({**_entity(nodes[0]), "open_incidents": incidents})


@tool("identity")
def identity_list_detections(limit: int = 10) -> str:
    """List recent identity incidents (the Identity Protection detections surface)."""
    q = (
        f"{{ incidents(first: {_clamp(limit)}) {{ nodes {{ incidentId type startTime endTime "
        "compromisedEntities { entityId primaryDisplayName } } } } }"
    )
    data, err = _graphql(q)
    if err:
        return err
    return _out(data.get("incidents", {}).get("nodes", []))


# ---------------------------------------------------------------- cloud

@tool("cloud")
def cloud_list_accounts(limit: int = 10) -> str:
    """List registered cloud accounts (AWS, Azure, GCP) from CSPM registration."""
    keys = ["account_id", "subscription_id", "tenant_id", "project_id", "parent_id", "organization_id", "status", "cloud_provider"]
    result = {}
    for provider, method in [("aws", "get_aws_account"), ("azure", "get_azure_account"), ("gcp", "get_gcp_account")]:
        body, err = _call(CSPMRegistration, method, limit=_clamp(limit))
        result[provider] = json.loads(err) if err else [_pick(a, keys) for a in body.get("resources", [])]
    return _out(result)


@tool("cloud")
def cloud_search_assets(filter: str | None = None, limit: int = 10) -> str:
    """Search the cloud asset inventory with an optional FQL filter, e.g. cloud_provider:'aws'."""
    kwargs = {"filter": filter} if filter else {}
    assets, err = _query_then_get(CloudSecurityAssets, "query_assets", "get_assets", "ids", limit, **kwargs)
    if err:
        return err
    keys = ["id", "resource_id", "resource_name", "resource_type", "cloud_provider", "account_id", "region", "status", "creation_time"]
    return _out([_pick(a, keys) for a in assets])


@tool("cloud")
def cloud_list_misconfigurations(severity: str | None = None, limit: int = 10) -> str:
    """List cloud misconfigurations (IOMs). severity: informational, low, medium, high, critical."""
    kwargs = {"filter": f"severity:'{_fql(severity.title())}'"} if severity else {}
    ioms, err = _query_then_get(CloudSecurityDetections, "query_iom_entities", "get_iom_entities", "ids", limit, **kwargs)
    if err:
        return err
    keys = ["id", "rule_name", "policy_statement", "severity", "status", "cloud_provider", "account_id", "region", "resource_type", "resource_id", "created_at"]
    return _out([_pick(i, keys) for i in ioms])


@tool("cloud")
def cloud_list_image_vulns(limit: int = 10) -> str:
    """List container image vulnerabilities, highest CVSS first."""
    body, err = _call(ContainerVulnerabilities, "read_combined_vulnerabilities", limit=_clamp(limit), sort="cvss_score|desc")
    if err:
        return err
    keys = ["cve_id", "severity", "cvss_score", "images_impacted", "containers_impacted", "packages_impacted", "exploited_status_name"]
    return _out([_pick(v, keys) for v in body.get("resources", [])])


# ------------------------------------------------------------ workflows

@tool("workflows")
def workflow_search_definitions(name: str | None = None, limit: int = 10) -> str:
    """Search Fusion workflow definitions, optionally by name substring."""
    kwargs = {"filter": f"name:~'{_fql(name)}'"} if name else {}
    body, err = _call(Workflows, "search_definitions", limit=_clamp(limit), **kwargs)
    if err:
        return err
    keys = ["id", "name", "description", "enabled", "last_modified_timestamp", "version"]
    return _out([_pick(d, keys) for d in body.get("resources", [])])


@tool("workflows")
def workflow_list_executions(definition_id: str | None = None, limit: int = 10) -> str:
    """List recent workflow executions, optionally for one definition."""
    kwargs = {"filter": f"definition_id:'{_fql(definition_id)}'"} if definition_id else {}
    body, err = _call(Workflows, "search_executions", limit=_clamp(limit), **kwargs)
    if err:
        return err
    keys = ["id", "definition_id", "workflow_name", "status", "start_timestamp", "end_timestamp", "trigger"]
    return _out([_pick(e, keys) for e in body.get("resources", [])])


@tool("workflows")
def workflow_get_execution(execution_id: str) -> str:
    """Get the status and results of one workflow execution."""
    body, err = _call(Workflows, "execution_results", ids=[execution_id])
    if err:
        return err
    resources = body.get("resources", [])
    return _out(resources[0]) if resources else _err("execution not found", 404)


@tool("workflows")
def workflow_execute(definition_id: str, params: dict | None = None, confirm: bool = False) -> str:
    """WRITE: run a workflow on demand. Requires ALLOW_WRITE=true and confirm=True."""
    if err := _write_guard(confirm):
        return err
    print(f"workflow_execute definition_id={definition_id}", file=sys.stderr)
    body, err = _call(Workflows, "execute", definition_id=definition_id, body=params or {})
    if err:
        return err
    return _out({"definition_id": definition_id, "execution_ids": body.get("resources")})


if __name__ == "__main__":
    mcp.run(transport="stdio")
