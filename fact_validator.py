UNKNOWN = "__unknown__"

CONFLICTS = [
    {
        "id": "C1", "mode": 1,
        "facts": ["requested_privilege_level", "requested_privileges_exceed_minimum"],
        "clash": lambda a: a.get("requested_privilege_level") == "view"
                           and a.get("requested_privileges_exceed_minimum") is True,
        "message": ("You said the requested level is View, the lowest level, but also that the "
                    "privileges exceed the minimum. Nothing can exceed View."),
    },
    {
        "id": "C2", "mode": 1,
        "facts": ["requested_privileges_exceed_minimum", "task_can_be_completed_with_lower_privilege"],
        "clash": lambda a: a.get("requested_privileges_exceed_minimum") is True
                           and a.get("task_can_be_completed_with_lower_privilege") is False,
        "message": ("You said the privileges exceed the minimum, but also that the task cannot be "
                    "done with lower privilege. If the request is above the minimum, a lower level "
                    "is by definition enough."),
    },
    {
        "id": "C3", "mode": 1,
        "facts": ["request_type", "access_type"],
        "clash": lambda a: a.get("request_type") == "break_glass"
                           and a.get("access_type") == "standard",
        "message": ("The request is marked as break-glass, but the access type is standard. "
                    "An emergency request should carry the break-glass access type."),
    },
    {
        "id": "C4", "mode": 1,
        "facts": ["access_type", "request_type"],
        "clash": lambda a: a.get("access_type") == "break_glass"
                           and a.get("request_type") == "standard",
        "message": ("The access type is break-glass, but the request is marked as standard. "
                    "Both should describe the same emergency."),
    },
    {
        "id": "C5", "mode": 2,
        "facts": ["port_1433_reachable", "sql_server_service_running"],
        "clash": lambda a: a.get("port_1433_reachable") is True
                           and a.get("sql_server_service_running") is False,
        "message": ("Port 1433 is reachable, but the SQL Server service is marked as stopped. "
                    "A reachable port needs a listening service behind it."),
    },
    {
        "id": "C6", "mode": 2,
        "facts": ["destination_vm_ip_reachable_from_source", "destination_vm_running"],
        "clash": lambda a: a.get("destination_vm_ip_reachable_from_source") is True
                           and a.get("destination_vm_running") is False,
        "message": ("The destination VM is marked as stopped, but its IP address is reachable "
                    "from the source. A stopped VM does not answer."),
    },
    {
        "id": "C7", "mode": 2,
        "facts": ["heartbeat_status", "credentials_valid_on_target"],
        "clash": lambda a: a.get("heartbeat_status") == "Success"
                           and a.get("credentials_valid_on_target") is False,
        "message": ("The heartbeat reports Success, but the stored credentials are marked as "
                    "invalid on the target. A successful heartbeat needs valid credentials."),
    },
    {
        "id": "C8", "mode": 2,
        "facts": ["port_443_listening", "iis_website_state"],
        "clash": lambda a: a.get("port_443_listening") is True
                           and a.get("iis_website_state") == "Stopped",
        "message": ("Port 443 is listening, but the IIS website is marked as stopped. "
                    "A stopped site does not serve that port."),
    },
]


def find_conflicts(answers, mode):
    found = []
    for c in CONFLICTS:
        if c["mode"] == mode and c["clash"](answers):
            found.append({"id": c["id"], "facts": list(c["facts"]), "message": c["message"]})
    return found


def find_stale_answers(answers, depends):
    stale = []
    for child, (parent, required) in depends.items():
        if child not in answers:
            continue
        parent_value = answers.get(parent, UNKNOWN)
        if parent_value == UNKNOWN or parent_value != required:
            stale.append(child)
    return stale