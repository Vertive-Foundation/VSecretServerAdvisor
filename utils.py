MODE_1_DEFAULTS = {
    "account_active": True,
    "account_not_locked": True,
    "within_business_hours": True,
    "account_type": "standard",
    "mfa_enabled": True,
    "mfa_assurance_level": "AAL2",

    "resource_sensitivity": "low",
    "requested_privilege_level": "view",
    "target_zone": "internal",
    "requester_role_not_authorized_for_high_sensitivity": False,
    "requested_privileges_exceed_minimum": False,
    "task_can_be_completed_with_lower_privilege": False,

    "secret_requires_approval": False,
    "requester_role_not_in_approval_group": False,
    "no_active_approval": False,
    "request_type": "standard",
    "required_approvers": 1,

    "session_type": "standard",
    "session_recording_enabled": True,
    "audit_logging_enabled": True,

    "secret_has_quantumlock_enabled": False,
    "rpc_rotation_enabled": False,
    "heartbeat_enabled": False,
    "secret_supports_checkout": False,
    "expiry_date_set": True,
    "secret_has_rotation_policy": False,
    "rpc_enabled": False,
    "last_rotation_status": "success",

    "days_since_last_rotation": 0,
    "rotation_interval": 30,

    "checkout_duration_hours": 0,

    "quantumlock_group_user_count": 2,
    "group_member_account_deleted": False,
    "no_recovery_path_available": False,
    "quantumlock_password_forgotten": False,

    "requester_role_owns_target_secret": False,
    "approver_role_same_group": False,
    "no_independent_approver": False,
    "dual_control_not_enabled": False,

    "access_type": "standard",
    "force_checkin_used": False,
    "no_justification_recorded": False,

    "event_pipeline_triggered_count": 0,
    "within_time_window_minutes": 0,
    "trigger_type_repeats": False,

    "connection_originates_from_internal_network": False,
    "vpn_tunnel_active": True,
    "source_ip_in_allowed_range": True,
}


MODE_2_DEFAULTS = {
    "secret_server_app_pool_start_mode": "AlwaysRunning",
    "app_pool_idle_timeout_minutes": 0,
    "app_pool_recycling_regular_interval": 0,
    "load_user_profile_enabled": True,
    "iis_https_binding_present": True,
    "ssl_certificate_valid": True,
    "iis_website_state": "Started",
    "port_443_listening": True,

    "sql_server_service_running": True,
    "port_1433_reachable": True,
    "sql_tcp_enabled": True,
    "sql_browser_service_running": True,
    "named_pipes_enabled": True,
    "sql_nocount_property": "off",
    "sql_response_time_ms": 100,

    "sql_server_collation": "SQL_Latin1_General_CP1_CI_AS",
    "database_collation": "SQL_Latin1_General_CP1_CI_AS",
    "sql_auth_mode": "mixed",
    "sql_account_password_policy_enforced": False,

    "sql_login_for_service_account_missing": False,
    "service_account_not_in_db_owner_role": False,

    "secret_server_app_version": "12.1.000002",
    "sql_database_schema_version": "12.1.000002",
    "app_vm_reverted_without_db_revert": False,
    "last_upgrade_attempt": "success",
    "db_owner_role_granted": True,
    "maintenance_mode_enabled": True,

    "source_vm_running": True,
    "destination_vm_running": True,
    "destination_vm_ip_reachable_from_source": True,

    "hostname_does_not_resolve_to_ip": False,
    "resolved_ip_does_not_match_expected": False,
    "dns_server_unreachable": False,
    "dns_zone_misconfigured": False,

    "ad_sync_secret_exists": True,
    "ad_sync_secret_credentials_invalid": False,
    "ad_sync_account_lacks_required_permissions": False,
    "domain_controller_reachable": True,
    "ad_domain_active_flag": True,

    "ad_credential_caching_enabled": False,
    "cached_credentials_age_days": 0,
    "entered_password_hash_matches_cached_hash": False,
    "ad_sync_returned_error": False,
    "ad_sync_returned_zero_users": False,
    "would_disable_all_users_in_domain": False,

    "heartbeat_enabled": True,
    "heartbeat_status": "Success",
    "last_heartbeat_status": "Success",
    "target_machine_reachable": True,
    "credentials_valid_on_target": True,
    "heartbeat_intermittent": False,

    "target_hostname_resolves_to_unexpected_ip": False,
    "secret_stored_hostname": "esxi01.lab.local",
    "resolved_ip": "192.168.100.75",
    "target_os": "windows",
    "ntlm_disabled_on_target": False,
    "account_not_in_domain": False,

    "target_system_type": "Windows",
    "root_credential_invalid": False,
    "esxi_host_unreachable": False,

    "primary_web_node_down": False,
    "traffic_not_redirected_to_secondary": False,
    "load_balancer_health_check_failing": False,
    "sql_alwayon_ag_state": "healthy",
    "sql_mirror_partner_unreachable": False,
}


MODE_1_PRESETS = [
    {
        "name": "Standard Request",
        "description": "All checks pass — request should be approved",
        "facts": {},
    },
    {
        "name": "Privileged Account, No MFA",
        "description": "Privileged account requesting access without MFA enabled",
        "facts": {
            "account_type": "privileged",
            "mfa_enabled": False,
            "mfa_assurance_level": "none",
            "resource_sensitivity": "high",
            "requested_privilege_level": "admin",
            "session_type": "privileged",
        },
    },
    {
        "name": "Emergency Break-glass Access",
        "description": "Emergency access to high-sensitivity resource without two-person control",
        "facts": {
            "request_type": "break_glass",
            "access_type": "break_glass",
            "resource_sensitivity": "high",
            "required_approvers": 1,
            "dual_control_not_enabled": True,
        },
    },
    {
        "name": "Conflicting Secret Configuration",
        "description": "Secret has QuantumLock, rotation, and heartbeat all enabled simultaneously",
        "facts": {
            "secret_has_quantumlock_enabled": True,
            "rpc_rotation_enabled": True,
            "heartbeat_enabled": True,
        },
    },
    {
        "name": "Separation of Duties Conflict",
        "description": "Requester and approver are in the same ownership group with no Dual Control",
        "facts": {
            "requester_role_owns_target_secret": True,
            "approver_role_same_group": True,
            "no_independent_approver": True,
            "dual_control_not_enabled": True,
        },
    },
    {
        "name": "Insider Threat Pattern",
        "description": "Privileged account without MFA and with a separation-of-duties violation — R4 and R10 fire, R14a and R14b follow, decision is DENY",
        "facts": {
            "account_type": "privileged",
            "mfa_enabled": False,
            "mfa_assurance_level": "none",
            "resource_sensitivity": "high",
            "requested_privilege_level": "admin",
            "session_type": "privileged",
            "requester_role_owns_target_secret": True,
            "approver_role_same_group": True,
            "no_independent_approver": True,
            "dual_control_not_enabled": True,
        },
    },
    {
        "name": "QuantumLock Data Loss Cascade",
        "description": "Single-member QuantumLock group whose account was deleted, and the password was forgotten — R5b fires, R5c follows, decision is DENY",
        "facts": {
            "secret_has_quantumlock_enabled": True,
            "quantumlock_group_user_count": 1,
            "group_member_account_deleted": True,
            "no_recovery_path_available": True,
            "quantumlock_password_forgotten": True,
        },
    },
]


MODE_2_PRESETS = [
    {
        "name": "All Systems Operational",
        "description": "All infrastructure healthy — no incidents detected",
        "facts": {},
    },
    {
        "name": "App/DB Version Mismatch",
        "description": "After a failed upgrade, app VM was reverted without reverting the database VM",
        "facts": {
            "secret_server_app_version": "12.0.000020",
            "sql_database_schema_version": "12.1.000002",
            "app_vm_reverted_without_db_revert": True,
            "last_upgrade_attempt": "failed",
            "db_owner_role_granted": True,
        },
    },
    {
        "name": "IIS Application Pool Misconfigured",
        "description": "IIS app pool settings cause Secret Server to randomly stop responding",
        "facts": {
            "secret_server_app_pool_start_mode": "OnDemand",
            "app_pool_idle_timeout_minutes": 20,
            "app_pool_recycling_regular_interval": 1740,
            "load_user_profile_enabled": False,
        },
    },
    {
        "name": "Heartbeat Credential Failure",
        "description": "Stored credentials no longer match the target system — out of sync",
        "facts": {
            "heartbeat_status": "Failed",
            "last_heartbeat_status": "Failed",
            "target_machine_reachable": True,
            "credentials_valid_on_target": False,
        },
    },
    {
        "name": "ESXi Root Credential Invalid",
        "description": "ESXi host reachable, but root credential stored in Secret Server is no longer valid",
        "facts": {
            "target_system_type": "ESXi",
            "target_os": "ESXi",
            "heartbeat_status": "Failed",
            "last_heartbeat_status": "Failed",
            "root_credential_invalid": True,
            "esxi_host_unreachable": False,
            "target_machine_reachable": True,
        },
    },
    {
        "name": "Active Directory Bind Failure",
        "description": "Secret Server cannot authenticate to Active Directory — sync secret credentials invalid",
        "facts": {
            "ad_sync_secret_credentials_invalid": True,
            "domain_controller_reachable": True,
            "ad_domain_active_flag": True,
        },
    },
    {
        "name": "SQL Server Unreachable",
        "description": "SQL Server service running but port 1433 not reachable from Secret Server",
        "facts": {
            "sql_server_service_running": True,
            "port_1433_reachable": False,
            "sql_tcp_enabled": True,
        },
    },
    {
        "name": "Cascading Upgrade Failure",
        "description": "Failed upgrade left app and database versions mismatched, maintenance mode off, and AD bind failing — R19 → R19a → R22c → R31",
        "facts": {
            "secret_server_app_version": "12.0.000020",
            "sql_database_schema_version": "12.1.000002",
            "app_vm_reverted_without_db_revert": True,
            "last_upgrade_attempt": "failed",
            "db_owner_role_granted": True,
            "maintenance_mode_enabled": False,
            "ad_sync_secret_credentials_invalid": True,
            "domain_controller_reachable": True,
            "ad_domain_active_flag": True,
            "ad_credential_caching_enabled": False,
        },
    },
    {
        "name": "Systemic Infrastructure Degradation",
        "description": "SQL responding slowly with intermittent heartbeats, and ESXi heartbeat failing — R17c (possible) + R23d → R29 (possible, capped at medium)",
        "facts": {
            "sql_response_time_ms": 850,
            "heartbeat_intermittent": True,
            "heartbeat_enabled": True,
            "heartbeat_status": "Failed",
            "last_heartbeat_status": "Failed",
            "target_machine_reachable": True,
            "credentials_valid_on_target": False,
            "target_system_type": "ESXi",
            "target_os": "ESXi",
            "root_credential_invalid": True,
            "esxi_host_unreachable": False,
        },
    },
]


FACT_LABELS = {
    "account_active": "Account is active",
    "account_not_locked": "Account is not locked",
    "within_business_hours": "Request within business hours",
    "account_type": "Account type",
    "mfa_enabled": "MFA enabled",
    "mfa_assurance_level": "MFA assurance level",
    "resource_sensitivity": "Resource sensitivity",
    "requested_privilege_level": "Requested privilege level",
    "target_zone": "Target zone",
    "requester_role_not_authorized_for_high_sensitivity": "Requester role not authorized for high sensitivity",
    "requested_privileges_exceed_minimum": "Requested privileges exceed minimum",
    "task_can_be_completed_with_lower_privilege": "Task can be completed with lower privilege",
    "secret_requires_approval": "Secret requires approval",
    "requester_role_not_in_approval_group": "Requester not in approval group",
    "no_active_approval": "No active approval",
    "request_type": "Request type",
    "required_approvers": "Required approvers",
    "session_type": "Session type",
    "session_recording_enabled": "Session recording enabled",
    "audit_logging_enabled": "Audit logging enabled",
    "secret_has_quantumlock_enabled": "QuantumLock enabled on secret",
    "rpc_rotation_enabled": "RPC rotation enabled",
    "heartbeat_enabled": "Heartbeat enabled",
    "secret_supports_checkout": "Secret supports checkout",
    "expiry_date_set": "Expiry date set",
    "secret_has_rotation_policy": "Secret has rotation policy",
    "rpc_enabled": "RPC enabled",
    "last_rotation_status": "Last rotation status",
    "days_since_last_rotation": "Days since last rotation",
    "rotation_interval": "Rotation interval (days)",
    "checkout_duration_hours": "Checkout duration (hours)",
    "quantumlock_group_user_count": "QuantumLock group user count",
    "group_member_account_deleted": "Group member account deleted",
    "no_recovery_path_available": "No recovery path available",
    "quantumlock_password_forgotten": "QuantumLock password forgotten",
    "requester_role_owns_target_secret": "Requester role owns target secret",
    "approver_role_same_group": "Approver in same group",
    "no_independent_approver": "No independent approver",
    "dual_control_not_enabled": "Dual Control not enabled",
    "access_type": "Access type",
    "force_checkin_used": "Forced check-in used",
    "no_justification_recorded": "No justification recorded",
    "event_pipeline_triggered_count": "Event Pipeline triggered count",
    "within_time_window_minutes": "Within time window (minutes)",
    "trigger_type_repeats": "Trigger type repeats",
    "connection_originates_from_internal_network": "Connection from internal network",
    "vpn_tunnel_active": "VPN tunnel active",
    "source_ip_in_allowed_range": "Source IP in allowed range",

    "secret_server_app_pool_start_mode": "App pool start mode",
    "app_pool_idle_timeout_minutes": "App pool idle timeout (min)",
    "app_pool_recycling_regular_interval": "App pool recycling interval (min)",
    "load_user_profile_enabled": "Load User Profile enabled",
    "iis_https_binding_present": "IIS HTTPS binding present",
    "ssl_certificate_valid": "SSL certificate valid",
    "iis_website_state": "IIS website state",
    "port_443_listening": "Port 443 listening",
    "sql_server_service_running": "SQL Server service running",
    "port_1433_reachable": "Port 1433 reachable",
    "sql_tcp_enabled": "SQL TCP enabled",
    "sql_browser_service_running": "SQL Browser service running",
    "named_pipes_enabled": "Named pipes enabled",
    "sql_nocount_property": "SQL NOCOUNT property",
    "sql_response_time_ms": "SQL response time (ms)",
    "sql_server_collation": "SQL Server collation",
    "database_collation": "Database collation",
    "sql_auth_mode": "SQL auth mode",
    "sql_account_password_policy_enforced": "Password policy enforced on service account",
    "sql_login_for_service_account_missing": "SQL login for service account missing",
    "service_account_not_in_db_owner_role": "Service account not in db_owner role",
    "secret_server_app_version": "Secret Server app version",
    "sql_database_schema_version": "SQL database schema version",
    "app_vm_reverted_without_db_revert": "App VM reverted without DB revert",
    "last_upgrade_attempt": "Last upgrade attempt",
    "db_owner_role_granted": "db_owner role granted",
    "maintenance_mode_enabled": "Maintenance mode enabled",
    "source_vm_running": "Source VM running",
    "destination_vm_running": "Destination VM running",
    "destination_vm_ip_reachable_from_source": "Destination VM reachable from source",
    "hostname_does_not_resolve_to_ip": "Hostname does not resolve to IP",
    "resolved_ip_does_not_match_expected": "Resolved IP does not match expected",
    "dns_server_unreachable": "DNS server unreachable",
    "dns_zone_misconfigured": "DNS zone misconfigured",
    "ad_sync_secret_exists": "AD sync secret exists",
    "ad_sync_secret_credentials_invalid": "AD sync secret credentials invalid",
    "ad_sync_account_lacks_required_permissions": "AD sync account lacks required permissions",
    "domain_controller_reachable": "Domain controller reachable",
    "ad_domain_active_flag": "AD domain marked active",
    "ad_credential_caching_enabled": "AD credential caching enabled",
    "cached_credentials_age_days": "Cached credentials age (days)",
    "entered_password_hash_matches_cached_hash": "Entered password matches cached hash",
    "ad_sync_returned_error": "AD sync returned error",
    "ad_sync_returned_zero_users": "AD sync returned zero users",
    "would_disable_all_users_in_domain": "Sync would disable all users in domain",
    "heartbeat_status": "Heartbeat status",
    "last_heartbeat_status": "Last heartbeat status",
    "target_machine_reachable": "Target machine reachable",
    "credentials_valid_on_target": "Credentials valid on target",
    "heartbeat_intermittent": "Heartbeat intermittent",
    "target_hostname_resolves_to_unexpected_ip": "Target hostname resolves to unexpected IP",
    "secret_stored_hostname": "Secret stored hostname",
    "resolved_ip": "Resolved IP",
    "target_os": "Target OS",
    "ntlm_disabled_on_target": "NTLM disabled on target",
    "account_not_in_domain": "Account not in domain",
    "target_system_type": "Target system type",
    "root_credential_invalid": "Root credential invalid",
    "esxi_host_unreachable": "ESXi host unreachable",
    "primary_web_node_down": "Primary web node down",
    "traffic_not_redirected_to_secondary": "Traffic not redirected to secondary",
    "load_balancer_health_check_failing": "Load balancer health check failing",
    "sql_alwayon_ag_state": "SQL AlwaysOn AG state",
    "sql_mirror_partner_unreachable": "SQL mirror partner unreachable",
}


MODE_1_SECTIONS = [
    ("Requester & Authentication", [
        "account_active", "account_not_locked", "within_business_hours",
        "account_type", "mfa_enabled", "mfa_assurance_level",
    ]),
    ("Resource & Privilege", [
        "resource_sensitivity", "requested_privilege_level", "target_zone",
        "requester_role_not_authorized_for_high_sensitivity",
        "requested_privileges_exceed_minimum",
        "task_can_be_completed_with_lower_privilege",
    ]),
    ("Workflow & Approval", [
        "secret_requires_approval", "requester_role_not_in_approval_group",
        "no_active_approval", "request_type", "required_approvers",
    ]),
    ("Session & Audit", [
        "session_type", "session_recording_enabled", "audit_logging_enabled",
    ]),
    ("Secret Configuration", [
        "secret_has_quantumlock_enabled", "rpc_rotation_enabled",
        "heartbeat_enabled", "secret_supports_checkout", "expiry_date_set",
        "secret_has_rotation_policy", "rpc_enabled", "last_rotation_status",
    ]),
    ("Credential Lifecycle", [
        "days_since_last_rotation", "rotation_interval",
        "checkout_duration_hours",
    ]),
    ("QuantumLock Risk", [
        "quantumlock_group_user_count", "group_member_account_deleted",
        "no_recovery_path_available", "quantumlock_password_forgotten",
    ]),
    ("Separation of Duties", [
        "requester_role_owns_target_secret", "approver_role_same_group",
        "no_independent_approver", "dual_control_not_enabled",
    ]),
    ("Break-glass Access", [
        "access_type", "force_checkin_used", "no_justification_recorded",
    ]),
    ("Event Pipeline", [
        "event_pipeline_triggered_count", "within_time_window_minutes",
        "trigger_type_repeats",
    ]),
    ("Network Exposure", [
        "connection_originates_from_internal_network", "vpn_tunnel_active",
        "source_ip_in_allowed_range",
    ]),
]

MODE_2_SECTIONS = [
    ("IIS Web Tier", [
        "secret_server_app_pool_start_mode", "app_pool_idle_timeout_minutes",
        "app_pool_recycling_regular_interval", "load_user_profile_enabled",
        "iis_https_binding_present", "ssl_certificate_valid",
        "iis_website_state", "port_443_listening",
    ]),
    ("SQL Server", [
        "sql_server_service_running", "port_1433_reachable", "sql_tcp_enabled",
        "sql_browser_service_running", "named_pipes_enabled", "sql_nocount_property",
        "sql_response_time_ms",
        "sql_server_collation", "database_collation", "sql_auth_mode",
        "sql_account_password_policy_enforced",
        "sql_login_for_service_account_missing", "service_account_not_in_db_owner_role",
    ]),
    ("App/DB Versioning", [
        "secret_server_app_version", "sql_database_schema_version",
        "app_vm_reverted_without_db_revert", "last_upgrade_attempt",
        "db_owner_role_granted", "maintenance_mode_enabled",
    ]),
    ("VM Network", [
        "source_vm_running", "destination_vm_running",
        "destination_vm_ip_reachable_from_source",
    ]),
    ("DNS Resolution", [
        "hostname_does_not_resolve_to_ip", "resolved_ip_does_not_match_expected",
        "dns_server_unreachable", "dns_zone_misconfigured",
    ]),
    ("Active Directory", [
        "ad_sync_secret_exists", "ad_sync_secret_credentials_invalid",
        "ad_sync_account_lacks_required_permissions", "domain_controller_reachable",
        "ad_domain_active_flag", "ad_credential_caching_enabled",
        "cached_credentials_age_days", "entered_password_hash_matches_cached_hash",
        "ad_sync_returned_error", "ad_sync_returned_zero_users",
        "would_disable_all_users_in_domain",
    ]),
    ("Heartbeat", [
        "heartbeat_enabled", "heartbeat_status", "last_heartbeat_status",
        "target_machine_reachable", "credentials_valid_on_target",
        "heartbeat_intermittent", "target_hostname_resolves_to_unexpected_ip",
        "secret_stored_hostname", "resolved_ip", "target_os",
        "ntlm_disabled_on_target", "account_not_in_domain",
    ]),
    ("ESXi", [
        "target_system_type", "root_credential_invalid", "esxi_host_unreachable",
    ]),
    ("HA / DR", [
        "primary_web_node_down", "traffic_not_redirected_to_secondary",
        "load_balancer_health_check_failing", "sql_alwayon_ag_state",
        "sql_mirror_partner_unreachable",
    ]),
]


def get_default_facts(mode):
    if mode == 1:
        return dict(MODE_1_DEFAULTS)
    elif mode == 2:
        return dict(MODE_2_DEFAULTS)
    else:
        raise ValueError(f"Invalid mode: {mode}. Must be 1 or 2.")


def apply_preset(mode, preset_index):
    if mode == 1:
        presets = MODE_1_PRESETS
        defaults = MODE_1_DEFAULTS
    elif mode == 2:
        presets = MODE_2_PRESETS
        defaults = MODE_2_DEFAULTS
    else:
        raise ValueError(f"Invalid mode: {mode}")

    if preset_index < 0 or preset_index >= len(presets):
        raise ValueError(f"Invalid preset index: {preset_index}")

    preset = presets[preset_index]
    facts = dict(defaults)
    facts.update(preset["facts"])
    return facts


def is_section_modified(current_facts, defaults, section_fact_keys):
    for key in section_fact_keys:
        if current_facts.get(key) != defaults.get(key):
            return True
    return False


def get_section_modified_map(mode, current_facts):
    if mode == 1:
        sections = MODE_1_SECTIONS
        defaults = MODE_1_DEFAULTS
    elif mode == 2:
        sections = MODE_2_SECTIONS
        defaults = MODE_2_DEFAULTS
    else:
        raise ValueError(f"Invalid mode: {mode}")

    return {
        i: is_section_modified(current_facts, defaults, section_keys)
        for i, (_, section_keys) in enumerate(sections)
    }