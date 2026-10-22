import json

import server


def show(name, result):
    print(f"\n== {name}\n{result[:800]}")
    return json.loads(result)


hosts = show("search_hosts", server.search_hosts(limit=3))
show("list_alerts", server.list_alerts(limit=3))

if isinstance(hosts, list) and hosts:
    device_id = hosts[0]["device_id"]
    show("get_host_details", server.get_host_details(device_id))
    show("get_host_containment_status", server.get_host_containment_status(device_id))
    # Without confirm=True these always refuse, so nothing is ever contained here.
    show("contain_host (no confirm)", server.contain_host(device_id))
    show("lift_containment (no confirm)", server.lift_containment(device_id))
else:
    print("\nNo hosts returned; skipped device-specific tools.")
