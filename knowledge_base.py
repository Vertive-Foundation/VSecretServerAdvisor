SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"


MODE_1_RULES = [

    {
        "id": "R1", "name": "Basic eligibility check", "mode": 1, "category": "eligibility",
        "conditions": [
            ("account_active", "==", True),
            ("account_not_locked", "==", True),
            ("within_business_hours", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("eligible_for_evaluation", True),
        "recommendation": "Requester is eligible for evaluation.",
        "severity": None,
    },

    {
        "id": "R2", "name": "Privilege-vs-resource sensitivity match", "mode": 1, "category": "privilege",
        "conditions": [
            ("resource_sensitivity", "==", "high"),
            ("requested_privilege_level", "==", "admin"),
            ("requester_role_not_authorized_for_high_sensitivity", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("elevated_review_required", True),
        "recommendation": "Escalate to a manager: a high-sensitivity resource is requested by a role not authorized for it.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R3", "name": "Least privilege violation", "mode": 1, "category": "privilege",
        "conditions": [
            ("requested_privileges_exceed_minimum", "==", True),
            ("task_can_be_completed_with_lower_privilege", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("least_privilege_violation", True),
        "recommendation": "Reduce the requested privileges to the minimum the task needs.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R4", "name": "MFA required for privileged accounts", "mode": 1, "category": "authentication",
        "conditions": [
            ("account_type", "==", "privileged"),
            ("mfa_enabled", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("mfa_required", True),
        "recommendation": "Enable MFA (FIDO2 recommended) before approving privileged access.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R5", "name": "AAL3 required for high-sensitivity resources", "mode": 1, "category": "authentication",
        "conditions": [
            ("resource_sensitivity", "==", "high"),
            ("mfa_assurance_level", "in", ["AAL1", "none"]),
        ],
        "logic": "AND",
        "conclusion": ("aal3_required", True),
        "recommendation": "Upgrade to AAL3-equivalent MFA (FIDO2 with a hardware key) for high-sensitivity access.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R5a", "name": "QuantumLock and RPC rotation conflict", "mode": 1, "category": "configuration",
        "conditions": [
            ("secret_has_quantumlock_enabled", "==", True),
            ("rpc_rotation_enabled", "==", True),
            ("heartbeat_enabled", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("quantumlock_rotation_conflict", True),
        "recommendation": "Disable QuantumLock, or disable RPC and heartbeat on this secret. QuantumLock disables RPC and prevents heartbeat, so the two cannot coexist.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R5b", "name": "QuantumLock single-user lockout risk", "mode": 1, "category": "configuration",
        "conditions": [
            ("quantumlock_group_user_count", "==", 1),
            ("group_member_account_deleted", "==", True),
            ("no_recovery_path_available", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("quantumlock_lockout_risk", True),
        "recommendation": "Add at least two users to the QuantumLock group. Delinea recommends this so the secrets stay accessible.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R6", "name": "Approval workflow required", "mode": 1, "category": "workflow",
        "conditions": [
            ("secret_requires_approval", "==", True),
            ("requester_role_not_in_approval_group", "==", True),
            ("no_active_approval", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("approval_workflow_required", True),
        "recommendation": "Submit the request through the approval workflow. The secret requires approval before access.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R7", "name": "Two-person approval for break-glass access", "mode": 1, "category": "workflow",
        "conditions": [
            ("request_type", "==", "break_glass"),
            ("resource_sensitivity", "==", "high"),
            ("required_approvers", "<", 2),
            ("dual_control_not_enabled", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("two_person_approval_required", True),
        "recommendation": "Configure two-person approval (Dual Control and a multi-approver workflow) for break-glass access to high-sensitivity resources.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R8", "name": "Session recording required for privileged sessions", "mode": 1, "category": "audit",
        "conditions": [
            ("session_type", "==", "privileged"),
            ("session_recording_enabled", "==", False),
            ("resource_sensitivity", "in", ["high", "critical"]),
        ],
        "logic": "AND",
        "conclusion": ("session_recording_required", True),
        "recommendation": "Enable session recording on this secret before granting privileged access.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R9", "name": "Credential rotation overdue", "mode": 1, "category": "lifecycle",
        "conditions": [
            ("secret_has_rotation_policy", "==", True),
            ("days_since_last_rotation", ">", {"ref": "rotation_interval"}),
            ("rpc_enabled", "==", True),
            ("last_rotation_status", "!=", "success"),
        ],
        "logic": "AND",
        "conclusion": ("rotation_overdue", True),
        "recommendation": "Re-run credential rotation. The last rotation failed or did not run within the interval.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R10", "name": "Separation of Duties violation", "mode": 1, "category": "governance",
        "conditions": [
            ("requester_role_owns_target_secret", "==", True),
            ("approver_role_same_group", "==", True),
            ("no_independent_approver", "==", True),
            ("dual_control_not_enabled", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("sod_violation", True),
        "recommendation": "Configure team-based visibility isolation or enable Dual Control to enforce separation of duties.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R11", "name": "Time-bound access not configured", "mode": 1, "category": "lifecycle",
        "conditions": [
            ("secret_supports_checkout", "==", True),
            ("expiry_date_set", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("time_bound_access_not_configured", True),
        "recommendation": "Set an expiry date on this secret. Indefinite access is not permitted for checkout-capable secrets.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R12", "name": "Break-glass audit violation", "mode": 1, "category": "audit",
        "conditions": [
            ("access_type", "==", "break_glass"),
            ("audit_logging_enabled", "==", False),
            ("force_checkin_used", "==", True),
            ("no_justification_recorded", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("break_glass_audit_violation", True),
        "recommendation": "Enable audit logging and require a justification for break-glass access.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R12a", "name": "Event Pipeline infinite loop detection", "mode": 1, "category": "meta",
        "conditions": [
            ("event_pipeline_triggered_count", ">=", 5),
            ("within_time_window_minutes", "==", 5),
            ("trigger_type_repeats", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("ep_infinite_loop_detected", True),
        "recommendation": "Investigate circular logic in the Event Pipelines.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R13", "name": "Network exposure violation for DMZ access", "mode": 1, "category": "network",
        "conditions": [
            ("target_zone", "in", ["DMZ", "internet_exposed"]),
            ("connection_originates_from_internal_network", "==", True),
            ("vpn_tunnel_active", "==", False),
            ("source_ip_in_allowed_range", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("network_exposure_violation", True),
        "recommendation": "Require a VPN tunnel or IP allowlisting for access to DMZ or internet-exposed resources.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R5c", "name": "QuantumLock data loss: sole user forgot password", "mode": 1, "category": "configuration",
        "conditions": [
            ("quantumlock_lockout_risk", "==", True),
            ("quantumlock_password_forgotten", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("quantumlock_data_loss_certain", True),
        "recommendation": "Resetting the QuantumLock password as the only member deletes the secret. Recovery is not possible from Secret Server; restore from a backup if one exists.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R11a", "name": "Checkout duration exceeds 24 hours (possible)", "mode": 1, "category": "lifecycle",
        "hedged": True,
        "conditions": [
            ("secret_supports_checkout", "==", True),
            ("expiry_date_set", "==", True),
            ("checkout_duration_hours", ">", 24),
        ],
        "logic": "AND",
        "conclusion": ("may_have_excessive_access", True),
        "recommendation": "Checkout duration exceeds 24 hours. Manual review is recommended to confirm the duration is justified.",
        "severity": SEVERITY_LOW,
    },

    {
        "id": "R14a", "name": "Insider threat pattern: MFA missing and SoD violation", "mode": 1, "category": "composite",
        "conditions": [
            ("mfa_required", "==", True),
            ("sod_violation", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("possible_insider_threat", True),
        "recommendation": "MFA is missing and a separation-of-duties violation exists together. Review the involved accounts and their access history.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R14b", "name": "Extreme access risk: insider pattern and certain data loss", "mode": 1, "category": "composite",
        "conditions": [
            ("quantumlock_data_loss_certain", "==", True),
            ("possible_insider_threat", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("extreme_access_risk", True),
        "recommendation": "An insider pattern and certain QuantumLock data loss are both present. Escalate to incident response.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R14", "name": "Final access decision", "mode": 1, "category": "decision",
        "logic": "DECISION_MATRIX",
        "computes": "decision",
        "conditions": [],
        "deny_triggers": [
            "least_privilege_violation", "mfa_required", "aal3_required",
            "quantumlock_rotation_conflict", "quantumlock_lockout_risk",
            "two_person_approval_required", "session_recording_required",
            "rotation_overdue", "sod_violation", "time_bound_access_not_configured",
            "break_glass_audit_violation", "ep_infinite_loop_detected",
            "network_exposure_violation",
            "quantumlock_data_loss_certain", "possible_insider_threat",
            "extreme_access_risk",
        ],
        "conclusion": ("final_decision", "<computed>"),
        "recommendation": "See the fired rules above for specific remediation steps.",
        "severity": None,
    },
]


MODE_2_RULES = [

    {
        "id": "R15", "name": "IIS app pool start mode is not AlwaysRunning", "mode": 2, "category": "web_tier",
        "conditions": [("secret_server_app_pool_start_mode", "!=", "AlwaysRunning")],
        "logic": "AND",
        "conclusion": ("iis_start_mode_wrong", True),
        "recommendation": "Set the app pool Start Mode to AlwaysRunning (Advanced Settings, General).",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R16", "name": "IIS app pool idle time-out is not 0", "mode": 2, "category": "web_tier",
        "conditions": [("app_pool_idle_timeout_minutes", "!=", 0)],
        "logic": "AND",
        "conclusion": ("iis_idle_timeout_set", True),
        "recommendation": "Set the app pool Idle Time-out to 0 (Advanced Settings, Process Model).",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R17", "name": "IIS app pool recycling interval is not 0", "mode": 2, "category": "web_tier",
        "conditions": [("app_pool_recycling_regular_interval", "!=", 0)],
        "logic": "AND",
        "conclusion": ("iis_recycling_interval_set", True),
        "recommendation": "Set Regular Time Interval to 0 and remove any Specific Times (Advanced Settings, Recycling).",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R18", "name": "IIS Load User Profile is disabled", "mode": 2, "category": "web_tier",
        "conditions": [("load_user_profile_enabled", "==", False)],
        "logic": "AND",
        "conclusion": ("iis_user_profile_not_loaded", True),
        "recommendation": "Set Load User Profile to True in the app pool Process Model, then run iisreset.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R19", "name": "IIS HTTPS binding missing", "mode": 2, "category": "web_tier",
        "conditions": [("iis_https_binding_present", "==", False)],
        "logic": "AND",
        "conclusion": ("iis_https_binding_missing", True),
        "recommendation": "Add or repair the HTTPS binding for the Secret Server site in IIS.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R20", "name": "SSL certificate invalid", "mode": 2, "category": "web_tier",
        "conditions": [("ssl_certificate_valid", "==", False)],
        "logic": "AND",
        "conclusion": ("ssl_certificate_invalid", True),
        "recommendation": "Install or renew a valid SSL certificate for the Secret Server site.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R21", "name": "IIS website is not started", "mode": 2, "category": "web_tier",
        "conditions": [("iis_website_state", "!=", "Started")],
        "logic": "AND",
        "conclusion": ("iis_website_stopped", True),
        "recommendation": "Start the Secret Server website in IIS Manager.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R22", "name": "Port 443 is not listening", "mode": 2, "category": "web_tier",
        "conditions": [("port_443_listening", "==", False)],
        "logic": "AND",
        "conclusion": ("port_443_not_listening", True),
        "recommendation": "Check that the site is bound to port 443 and that no firewall rule is blocking it.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R23", "name": "SQL Server service is stopped", "mode": 2, "category": "database_tier",
        "conditions": [("sql_server_service_running", "==", False)],
        "logic": "AND",
        "conclusion": ("sql_service_stopped", True),
        "recommendation": "Start the SQL Server service.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R24", "name": "Port 1433 is blocked", "mode": 2, "category": "database_tier",
        "conditions": [("port_1433_reachable", "==", False)],
        "logic": "AND",
        "conclusion": ("sql_port_1433_blocked", True),
        "recommendation": "Allow TCP 1433 between Secret Server and SQL Server, and confirm SQL Server is listening on it.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R25", "name": "SQL TCP/IP is disabled", "mode": 2, "category": "database_tier",
        "conditions": [("sql_tcp_enabled", "==", False)],
        "logic": "AND",
        "conclusion": ("sql_tcp_disabled", True),
        "recommendation": "Enable TCP/IP in SQL Server Configuration Manager under Protocols for MSSQLSERVER, then restart SQL Server.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R26", "name": "SQL Server Browser is stopped", "mode": 2, "category": "database_tier",
        "conditions": [("sql_browser_service_running", "==", False)],
        "logic": "AND",
        "conclusion": ("sql_browser_stopped", True),
        "recommendation": "Start the SQL Server Browser service. It is needed for named instances and remote connections.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R27", "name": "Named pipes are disabled", "mode": 2, "category": "database_tier",
        "conditions": [("named_pipes_enabled", "==", False)],
        "logic": "AND",
        "conclusion": ("sql_named_pipes_disabled", True),
        "recommendation": "Enable Named Pipes in SQL Server Configuration Manager, then restart SQL Server.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R28", "name": "SQL NOCOUNT property is on", "mode": 2, "category": "database_tier",
        "conditions": [("sql_nocount_property", "==", "on")],
        "logic": "AND",
        "conclusion": ("sql_nocount_on", True),
        "recommendation": "Turn the NOCOUNT connection property off. With it on, no Secret Server jobs will run.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R29", "name": "Server collation is not SQL_Latin1_General_CP1_CI_AS", "mode": 2, "category": "database_tier",
        "conditions": [("sql_server_collation", "!=", "SQL_Latin1_General_CP1_CI_AS")],
        "logic": "AND",
        "conclusion": ("server_collation_wrong", True),
        "recommendation": "Set the server collation to SQL_Latin1_General_CP1_CI_AS, as the install guide requires.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R30", "name": "Database collation differs from server collation", "mode": 2, "category": "database_tier",
        "conditions": [("database_collation", "!=", {"ref": "sql_server_collation"})],
        "logic": "AND",
        "conclusion": ("database_collation_differs", True),
        "recommendation": "Rebuild the database with the same collation as the server.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R31", "name": "Mixed mode is off", "mode": 2, "category": "database_tier",
        "conditions": [("sql_auth_mode", "!=", "mixed")],
        "logic": "AND",
        "conclusion": ("mixed_mode_off", True),
        "recommendation": "Enable mixed mode only if Secret Server uses a SQL account. Set it in SQL Server Management Studio (instance Security properties), then restart SQL Server.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R32", "name": "SQL login for the service account is missing", "mode": 2, "category": "database_tier",
        "conditions": [("sql_login_for_service_account_missing", "==", True)],
        "logic": "AND",
        "conclusion": ("sql_login_missing", True),
        "recommendation": "Create a SQL login for the service account. This is needed only when SQL authentication is used.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R33", "name": "Service account is not in the db_owner role", "mode": 2, "category": "database_tier",
        "conditions": [("service_account_not_in_db_owner_role", "==", True)],
        "logic": "AND",
        "conclusion": ("not_db_owner", True),
        "recommendation": "Grant db_owner on the Secret Server database to the service account.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R34", "name": "Password policy is enforced on the service account", "mode": 2, "category": "database_tier",
        "conditions": [("sql_account_password_policy_enforced", "==", True)],
        "logic": "AND",
        "conclusion": ("password_policy_enforced", True),
        "recommendation": "Exempt the SQL service account from the password policy, or its login may fail.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R35", "name": "App/DB version mismatch after a failed upgrade", "mode": 2, "category": "upgrade",
        "conditions": [
            ("secret_server_app_version", "!=", {"ref": "sql_database_schema_version"}),
            ("app_vm_reverted_without_db_revert", "==", True),
            ("last_upgrade_attempt", "==", "failed"),
            ("db_owner_role_granted", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("app_db_version_mismatch", True),
        "recommendation": "Coordinated recovery is required: enable maintenance mode, stop the IIS site, restore the database from a coordinated backup, restore the app VM to a matching version, and reactivate the license.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R36", "name": "VM-to-VM network unreachable", "mode": 2, "category": "network",
        "conditions": [
            ("source_vm_running", "==", True),
            ("destination_vm_running", "==", True),
            ("destination_vm_ip_reachable_from_source", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("vm_to_vm_network_failure", True),
        "recommendation": "Check the virtual switch, port group, firewall rules, and IP configuration on both VMs.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R36a", "name": "Source VM is stopped", "mode": 2, "category": "network",
        "conditions": [("source_vm_running", "==", False)],
        "logic": "AND",
        "conclusion": ("source_vm_stopped", True),
        "recommendation": "Start the source VM. VM-to-VM connectivity cannot be checked while it is stopped.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R36b", "name": "Destination VM is stopped", "mode": 2, "category": "network",
        "conditions": [("destination_vm_running", "==", False)],
        "logic": "AND",
        "conclusion": ("destination_vm_stopped", True),
        "recommendation": "Start the destination VM, then re-test connectivity from the source.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R37", "name": "Hostname does not resolve to an IP", "mode": 2, "category": "network",
        "conditions": [("hostname_does_not_resolve_to_ip", "==", True)],
        "logic": "AND",
        "conclusion": ("hostname_unresolved", True),
        "recommendation": "Check the DNS record for the hostname and any host file overrides.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R38", "name": "Resolved IP does not match the expected IP", "mode": 2, "category": "network",
        "conditions": [("resolved_ip_does_not_match_expected", "==", True)],
        "logic": "AND",
        "conclusion": ("dns_ip_mismatch", True),
        "recommendation": "Check the DNS record and the DNS cache on the Secret Server host against the expected address.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R39", "name": "DNS server unreachable", "mode": 2, "category": "network",
        "conditions": [("dns_server_unreachable", "==", True)],
        "logic": "AND",
        "conclusion": ("dns_server_down", True),
        "recommendation": "Check that the DNS server is running and reachable from Secret Server.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R40", "name": "DNS zone misconfigured", "mode": 2, "category": "network",
        "conditions": [("dns_zone_misconfigured", "==", True)],
        "logic": "AND",
        "conclusion": ("dns_zone_wrong", True),
        "recommendation": "Check the DNS zone configuration for the Secret Server host records.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R41", "name": "AD sync secret is missing", "mode": 2, "category": "identity",
        "conditions": [("ad_sync_secret_exists", "==", False)],
        "logic": "AND",
        "conclusion": ("ad_sync_secret_missing", True),
        "recommendation": "Create the AD sync secret in Secret Server.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R42", "name": "AD sync secret credentials are invalid", "mode": 2, "category": "identity",
        "conditions": [("ad_sync_secret_credentials_invalid", "==", True)],
        "logic": "AND",
        "conclusion": ("ad_sync_creds_invalid", True),
        "recommendation": "Update the AD sync secret with valid credentials.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R43", "name": "AD sync account lacks required permissions", "mode": 2, "category": "identity",
        "conditions": [("ad_sync_account_lacks_required_permissions", "==", True)],
        "logic": "AND",
        "conclusion": ("ad_sync_permissions_missing", True),
        "recommendation": "Grant the AD sync account the permissions the sync requires.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R44", "name": "Domain controller unreachable", "mode": 2, "category": "identity",
        "conditions": [("domain_controller_reachable", "==", False)],
        "logic": "AND",
        "conclusion": ("dc_unreachable", True),
        "recommendation": "Restore connectivity to the domain controller.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R45", "name": "AD domain is not marked active", "mode": 2, "category": "identity",
        "conditions": [("ad_domain_active_flag", "==", False)],
        "logic": "AND",
        "conclusion": ("ad_domain_inactive", True),
        "recommendation": "Mark the domain as active in Secret Server directory settings.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R46", "name": "AD cache granted login (domain controller down)", "mode": 2, "category": "identity",
        "conditions": [
            ("domain_controller_reachable", "==", False),
            ("ad_credential_caching_enabled", "==", True),
            ("cached_credentials_age_days", "<=", 30),
            ("entered_password_hash_matches_cached_hash", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("ad_cache_login_granted", True),
        "recommendation": "Login was granted from cached credentials. Restore domain controller access, because the cache expires after 30 days.",
        "severity": SEVERITY_LOW,
    },

    {
        "id": "R47", "name": "AD sync returned an error", "mode": 2, "category": "identity",
        "conditions": [("ad_sync_returned_error", "==", True)],
        "logic": "AND",
        "conclusion": ("ad_sync_error", True),
        "recommendation": "Read the AD sync error in the Secret Server logs before retrying the sync.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R48", "name": "AD sync returned zero users", "mode": 2, "category": "identity",
        "conditions": [("ad_sync_returned_zero_users", "==", True)],
        "logic": "AND",
        "conclusion": ("ad_sync_zero_users", True),
        "recommendation": "Check the AD sync scope and the directory path. An empty result can come from a wrong scope.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R49", "name": "Sync would disable all users in the domain", "mode": 2, "category": "identity",
        "conditions": [("would_disable_all_users_in_domain", "==", True)],
        "logic": "AND",
        "conclusion": ("ad_sync_safeguard", True),
        "recommendation": "The safeguard stopped a destructive sync. Investigate the AD sync source before retrying.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R50", "name": "Heartbeat credential check failed", "mode": 2, "category": "heartbeat",
        "conditions": [
            ("heartbeat_enabled", "==", True),
            ("last_heartbeat_status", "==", "Failed"),
            ("target_machine_reachable", "==", True),
            ("credentials_valid_on_target", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("heartbeat_failed", True),
        "recommendation": "Credentials are out of sync with the target. Trigger RPC rotation to update the stored credential.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R51", "name": "DNS mismatch detected via heartbeat", "mode": 2, "category": "heartbeat",
        "conditions": [
            ("heartbeat_status", "==", "DnsMismatch"),
            ("target_hostname_resolves_to_unexpected_ip", "==", True),
            ("secret_stored_hostname", "!=", {"ref": "resolved_ip"}),
        ],
        "logic": "AND",
        "conclusion": ("dns_mismatch_detected", True),
        "recommendation": "Investigate DNS resolution for the target host, host file overrides, or possible DNS poisoning.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R52", "name": "Authentication protocol mismatch", "mode": 2, "category": "heartbeat",
        "conditions": [
            ("heartbeat_status", "==", "AuthProtocolUnavailable"),
            ("target_os", "==", "windows"),
            ("ntlm_disabled_on_target", "==", True),
            ("account_not_in_domain", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("auth_protocol_mismatch", True),
        "recommendation": "Use the UPN form (user@domain.com), join the target to the domain, or review NTLM policy on the target.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R53", "name": "ESXi root credential invalid", "mode": 2, "category": "heartbeat",
        "conditions": [
            ("target_system_type", "==", "ESXi"),
            ("heartbeat_status", "==", "Failed"),
            ("root_credential_invalid", "==", True),
            ("esxi_host_unreachable", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("esxi_root_credential_invalid", True),
        "recommendation": "Rotate the root credential through vSphere, update the Secret Server secret, and re-run the heartbeat.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R54", "name": "Primary web node is down", "mode": 2, "category": "availability",
        "conditions": [("primary_web_node_down", "==", True)],
        "logic": "AND",
        "conclusion": ("primary_web_node_down_finding", True),
        "recommendation": "Bring the primary web node back up, or confirm the secondary is serving requests.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R55", "name": "Traffic is not redirected to the secondary node", "mode": 2, "category": "availability",
        "conditions": [("traffic_not_redirected_to_secondary", "==", True)],
        "logic": "AND",
        "conclusion": ("traffic_not_failed_over", True),
        "recommendation": "Check the load balancer routing so traffic reaches the secondary when the primary is down.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R56", "name": "Load balancer health check failing", "mode": 2, "category": "availability",
        "conditions": [("load_balancer_health_check_failing", "==", True)],
        "logic": "AND",
        "conclusion": ("lb_health_check_failing", True),
        "recommendation": "Check the load balancer health check configuration and the node responses it probes.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R57", "name": "SQL AlwaysOn availability group is unhealthy", "mode": 2, "category": "availability",
        "conditions": [("sql_alwayon_ag_state", "!=", "healthy")],
        "logic": "AND",
        "conclusion": ("alwayson_unhealthy", True),
        "recommendation": "Check the AlwaysOn availability group state and its synchronization health.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R58", "name": "SQL mirror partner unreachable", "mode": 2, "category": "availability",
        "conditions": [("sql_mirror_partner_unreachable", "==", True)],
        "logic": "AND",
        "conclusion": ("mirror_partner_unreachable", True),
        "recommendation": "Check that the SQL mirror partner is reachable and that automatic failover is configured.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R59", "name": "IIS app pool settings are wrong", "mode": 2, "category": "web_tier",
        "conditions": [
            ("iis_start_mode_wrong", "==", True),
            ("iis_idle_timeout_set", "==", True),
            ("iis_recycling_interval_set", "==", True),
            ("iis_user_profile_not_loaded", "==", True),
        ],
        "logic": "OR",
        "conclusion": ("iis_app_pool_misconfigured", True),
        "recommendation": "One or more app pool settings are wrong. See the specific findings.",
        "severity": None,
    },

    {
        "id": "R60", "name": "IIS HTTPS is unreachable", "mode": 2, "category": "web_tier",
        "conditions": [
            ("iis_https_binding_missing", "==", True),
            ("ssl_certificate_invalid", "==", True),
            ("iis_website_stopped", "==", True),
            ("port_443_not_listening", "==", True),
        ],
        "logic": "OR",
        "conclusion": ("iis_https_unreachable", True),
        "recommendation": "One or more HTTPS settings are wrong. See the specific findings.",
        "severity": None,
    },

    {
        "id": "R61", "name": "SQL access is impaired", "mode": 2, "category": "database_tier",
        "conditions": [
            ("sql_service_stopped", "==", True),
            ("sql_port_1433_blocked", "==", True),
            ("sql_tcp_disabled", "==", True),
            ("sql_browser_stopped", "==", True),
            ("sql_named_pipes_disabled", "==", True),
            ("sql_nocount_on", "==", True),
        ],
        "logic": "OR",
        "conclusion": ("sql_access_impaired", True),
        "recommendation": "One or more SQL access settings are wrong. See the specific findings.",
        "severity": None,
    },

    {
        "id": "R62", "name": "AD bind failed", "mode": 2, "category": "identity",
        "conditions": [
            ("ad_sync_secret_missing", "==", True),
            ("ad_sync_creds_invalid", "==", True),
            ("ad_sync_permissions_missing", "==", True),
            ("dc_unreachable", "==", True),
            ("ad_domain_inactive", "==", True),
        ],
        "logic": "OR",
        "conclusion": ("ad_bind_failed", True),
        "recommendation": "AD bind failed. See the specific AD findings.",
        "severity": None,
    },

    {
        "id": "R63", "name": "Full web tier outage", "mode": 2, "category": "web_tier",
        "conditions": [
            ("iis_app_pool_misconfigured", "==", True),
            ("iis_https_unreachable", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("full_web_tier_outage", True),
        "recommendation": "The app pool settings and the HTTPS settings are both wrong. Fix both sets of findings above; the site will not serve requests until both are correct.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R64", "name": "SQL slow, possibly degraded (partial evidence)", "mode": 2, "category": "database_tier",
        "hedged": True,
        "conditions": [
            ("sql_access_impaired", "==", False),
            ("sql_response_time_ms", ">", 500),
            ("heartbeat_intermittent", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("may_have_sql_degradation", True),
        "recommendation": "SQL is reachable but slow, and heartbeats are intermittent. This MAY be database degradation. Check blocking and isolation settings per the SQL performance guidance.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R65", "name": "Maintenance mode not enabled during app/DB mismatch", "mode": 2, "category": "upgrade",
        "conditions": [
            ("app_db_version_mismatch", "==", True),
            ("maintenance_mode_enabled", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("recovery_mode_required", True),
        "recommendation": "Enable maintenance mode and stop the Secret Server IIS site before any database recovery step.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R66", "name": "AD bind failed with no cache fallback", "mode": 2, "category": "identity",
        "conditions": [
            ("ad_bind_failed", "==", True),
            ("ad_cache_login_granted", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("cascading_ad_failure", True),
        "recommendation": "AD bind failed and no cached-credential fallback applied. Restore domain controller connectivity, or enable AD credential caching if it suits this environment.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R67", "name": "Heartbeat failure on critical infrastructure (ESXi)", "mode": 2, "category": "heartbeat",
        "conditions": [
            ("heartbeat_failed", "==", True),
            ("target_system_type", "in", ["ESXi"]),
        ],
        "logic": "AND",
        "conclusion": ("critical_infra_heartbeat_failure", True),
        "recommendation": "Heartbeat failed on an ESXi target. Rotate the root credential through vSphere, update the secret, and re-run the heartbeat.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R68", "name": "Systemic infrastructure degradation (possible)", "mode": 2, "category": "composite",
        "conditions": [
            ("may_have_sql_degradation", "==", True),
            ("critical_infra_heartbeat_failure", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("systemic_infra_degradation", True),
        "recommendation": "SQL degradation and an ESXi heartbeat failure appear together. Check shared dependencies such as network, storage, and hypervisor health.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R69", "name": "Total environment failure", "mode": 2, "category": "composite",
        "conditions": [
            ("full_web_tier_outage", "==", True),
            ("cascading_ad_failure", "==", True),
            ("recovery_mode_required", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("total_environment_failure", True),
        "recommendation": "The web tier, AD authentication, and database recovery are all failing together. Plan a coordinated recovery, and escalate to Delinea support if the system cannot be brought back.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R70", "name": "Failed upgrade with AD authentication failure", "mode": 2, "category": "composite",
        "conditions": [
            ("recovery_mode_required", "==", True),
            ("cascading_ad_failure", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("post_upgrade_cascading_failure", True),
        "recommendation": "A version mismatch from a failed upgrade and an AD authentication failure are both present. Restore the database and app versions together, then re-test the AD bind before declaring recovery complete.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R71", "name": "Recommended next diagnostic step", "mode": 2, "category": "decision",
        "conditions": [],
        "logic": "PRIORITY_FIRST",
        "computes": "next_step",
        "conclusion": ("next_step", "<computed>"),
        "recommendation": "See the highest-severity confirmed cause for the specific action.",
        "severity": None,
    },

    {
        "id": "R72", "name": "Severity scoring", "mode": 2, "category": "decision",
        "conditions": [],
        "logic": "PRIORITY_FIRST",
        "computes": "severity",
        "conclusion": ("severity", "<computed>"),
        "recommendation": "Severity is taken from the highest-severity confirmed cause.",
        "severity": None,
    },
]


ALL_RULES = MODE_1_RULES + MODE_2_RULES