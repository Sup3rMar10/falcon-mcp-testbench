import json
import sys

import server

# usage: smoke_test.py [module ...] [--write]   (modules: hosts alerts identity cloud workflows)
args = [a for a in sys.argv[1:] if a != "--write"]
write = "--write" in sys.argv
wanted = set(args) or {"hosts", "alerts", "identity", "cloud", "workflows"}


def show(name, result):
    print(f"\n== {name}\n{result[:600]}")
    return json.loads(result)


def first_id(result, key="id"):
    return result[0].get(key) if isinstance(result, list) and result else None


if "hosts" in wanted:
    hosts = show("search_hosts", server.search_hosts(limit=3))
    if first_id(hosts, "device_id"):
        show("get_host_containment_status", server.get_host_containment_status(first_id(hosts, "device_id")))
    # Without confirm=True this always refuses, so nothing is ever contained here.
    show("contain_host (no confirm)", server.contain_host("smoke-test-id"))

if "alerts" in wanted:
    show("list_alerts", server.list_alerts(limit=3))

if "identity" in wanted:
    show("identity_list_detections", server.identity_list_detections(limit=3))
    show("identity_search_entities", server.identity_search_entities("a", limit=3))

if "cloud" in wanted:
    show("cloud_list_accounts", server.cloud_list_accounts(limit=3))
    show("cloud_search_assets", server.cloud_search_assets(limit=3))
    show("cloud_list_misconfigurations", server.cloud_list_misconfigurations(limit=3))
    show("cloud_list_image_vulns", server.cloud_list_image_vulns(limit=3))

if "workflows" in wanted:
    defs = show("workflow_search_definitions", server.workflow_search_definitions(limit=3))
    show("workflow_list_executions", server.workflow_list_executions(limit=3))
    execs = json.loads(server.workflow_list_executions(limit=1))
    if first_id(execs):
        show("workflow_get_execution", server.workflow_get_execution(first_id(execs)))
    # Real execution only with --write (and still needs ALLOW_WRITE=true in the environment).
    if write and first_id(defs):
        print(f"\n--write: executing definition {first_id(defs)}")
        show("workflow_execute", server.workflow_execute(first_id(defs), confirm=True))
    else:
        show("workflow_execute (no confirm)", server.workflow_execute("smoke-test-id"))
