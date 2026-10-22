import json
import os

from falconpy import Alerts, Hosts
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("falcon-testbench")


def _out(data):
    return json.dumps(data, separators=(",", ":"), default=str)


def _err(msg, status=None):
    return _out({"error": msg, **({"status_code": status} if status else {})})


def _creds():
    cid, secret = os.environ.get("FALCON_CLIENT_ID"), os.environ.get("FALCON_CLIENT_SECRET")
    if not cid or not secret:
        return None
    base = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com")
    return {"client_id": cid, "client_secret": secret, "base_url": base}


def _api_error(resp):
    """Return a JSON error string if the FalconPy response failed, else None."""
    code = resp.get("status_code")
    if code and 200 <= code < 300:
        return None
    errors = resp.get("body", {}).get("errors") or []
    msg = "; ".join(e.get("message", "") for e in errors) or "request failed"
    return _err(msg, code)


def _fql(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _clamp(limit):
    return max(1, min(limit, 100))


def _host_ids(filter_fql, limit):
    """Query host IDs; returns (ids, error_json)."""
    auth = _creds()
    if not auth:
        return None, _err("FALCON_CLIENT_ID / FALCON_CLIENT_SECRET not set")
    r = Hosts(**auth).query_devices_by_filter(filter=filter_fql, limit=_clamp(limit))
    return r["body"].get("resources", []), _api_error(r)


def _host_details(ids):
    """Fetch full host records; returns (records, error_json)."""
    if not ids:
        return [], None
    r = Hosts(**_creds()).get_device_details(ids=ids)
    return r["body"].get("resources", []), _api_error(r)


@mcp.tool()
def search_hosts(hostname: str | None = None, status: str | None = None, limit: int = 10) -> str:
    """Search hosts by hostname (substring) and/or status (normal, contained, containment_pending, lift_containment_pending)."""
    parts = []
    if hostname:
        parts.append(f"hostname:*'*{_fql(hostname)}*'")
    if status:
        parts.append(f"status:'{_fql(status)}'")
    ids, err = _host_ids("+".join(parts), limit)
    if err:
        return err
    hosts, err = _host_details(ids)
    if err:
        return err
    keys = ["device_id", "hostname", "platform_name", "status", "last_seen", "agent_version"]
    return _out([{("platform" if k == "platform_name" else k): h.get(k) for k in keys} for h in hosts])


@mcp.tool()
def get_host_details(device_id: str) -> str:
    """Get the full Falcon record for one host."""
    if not _creds():
        return _err("FALCON_CLIENT_ID / FALCON_CLIENT_SECRET not set")
    hosts, err = _host_details([device_id])
    if err:
        return err
    return _out(hosts[0]) if hosts else _err("host not found", 404)


@mcp.tool()
def list_alerts(severity: str | None = None, limit: int = 10) -> str:
    """List recent alerts, newest first. severity: Informational, Low, Medium, High, Critical."""
    auth = _creds()
    if not auth:
        return _err("FALCON_CLIENT_ID / FALCON_CLIENT_SECRET not set")
    alerts = Alerts(**auth)
    fql = f"severity_name:'{_fql(severity.title())}'" if severity else ""
    q = alerts.query_alerts_v2(filter=fql, limit=_clamp(limit), sort="created_timestamp.desc")
    if err := _api_error(q):
        return err
    ids = q["body"].get("resources", [])
    if not ids:
        return _out([])
    d = alerts.get_alerts_v2(composite_ids=ids)
    if err := _api_error(d):
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
        for a in d["body"].get("resources", [])
    ])


@mcp.tool()
def get_host_containment_status(device_id: str) -> str:
    """Get the containment status of a host (normal, contained, containment_pending, lift_containment_pending)."""
    if not _creds():
        return _err("FALCON_CLIENT_ID / FALCON_CLIENT_SECRET not set")
    hosts, err = _host_details([device_id])
    if err:
        return err
    if not hosts:
        return _err("host not found", 404)
    status = hosts[0].get("status")
    return _out({"device_id": device_id, "status": status, "contained": status == "contained"})


def _write_action(action, device_id, confirm):
    if os.environ.get("ALLOW_WRITE", "false").lower() != "true":
        return _err("write actions disabled: set ALLOW_WRITE=true")
    if confirm is not True:
        return _err("confirm=True is required")
    auth = _creds()
    if not auth:
        return _err("FALCON_CLIENT_ID / FALCON_CLIENT_SECRET not set")
    r = Hosts(**auth).perform_action(action_name=action, ids=[device_id])
    if err := _api_error(r):
        return err
    return _out({"device_id": device_id, "action": action, "result": r["body"].get("resources")})


@mcp.tool()
def contain_host(device_id: str, confirm: bool = False) -> str:
    """WRITE: network-contain a host. Requires ALLOW_WRITE=true and confirm=True."""
    return _write_action("contain", device_id, confirm)


@mcp.tool()
def lift_containment(device_id: str, confirm: bool = False) -> str:
    """WRITE: lift network containment on a host. Requires ALLOW_WRITE=true and confirm=True."""
    return _write_action("lift_containment", device_id, confirm)


if __name__ == "__main__":
    mcp.run(transport="stdio")
