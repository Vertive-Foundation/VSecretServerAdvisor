SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

HEARTBEAT_STATUSES = [
    "Success", "Failed", "UnableToConnect", "UnknownError",
    "DnsMismatch", "AccountLockedOut", "AuthProtocolUnavailable",
    "IncompatibleHost", "PrivilegedAccountRequired",
    "UnableToValidateServerPublicKey", "ArgumentError", "Disabled",
    "Failed Unknown", "NeedsImmediateRetry", "Pending", "Processing",
]

ACCOUNT_TYPES = ["standard", "privileged"]
SENSITIVITY_LEVELS = ["low", "medium", "high", "critical"]
RESOURCE_ZONES = ["internal", "DMZ", "internet_exposed"]

MODE_1_RULES = [

    {
        "id": "R1",
        "name": "Basic eligibility check",
        "mode": 1,
        "category": "eligibility",
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
        "id": "R2",
        "name": "Privilege-vs-resource sensitivity match",
        "mode": 1,
        "category": "privilege",
        "conditions": [
            ("resource_sensitivity", "==", "high"),
            ("requested_privilege_level", "==", "admin"),
            ("requester_role_not_authorized_for_high_sensitivity", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("elevated_review_required", True),
        "recommendation": "Escalate to manager — high-sensitivity resource requested by non-authorized role.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R3",
        "name": "Least privilege violation",
        "mode": 1,
        "category": "privilege",
        "conditions": [
            ("requested_privileges_exceed_minimum", "==", True),
            ("task_can_be_completed_with_lower_privilege", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("least_privilege_violation", True),
        "recommendation": "Reduce requested privileges to the minimum required for the task.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R4",
        "name": "MFA required for privileged accounts",
        "mode": 1,
        "category": "authentication",
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
        "id": "R5",
        "name": "AAL3 required for high-sensitivity resources",
        "mode": 1,
        "category": "authentication",
        "conditions": [
            ("resource_sensitivity", "==", "high"),
            ("mfa_assurance_level", "in", ["AAL1", "none"]),
        ],
        "logic": "AND",
        "conclusion": ("aal3_required", True),
        "recommendation": "Upgrade to AAL3-equivalent MFA (FIDO2 with hardware key) for high-sensitivity access.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R5a",
        "name": "QuantumLock / RPC rotation conflict",
        "mode": 1,
        "category": "configuration",
        "conditions": [
            ("secret_has_quantumlock_enabled", "==", True),
            ("rpc_rotation_enabled", "==", True),
            ("heartbeat_enabled", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("quantumlock_rotation_conflict", True),
        "recommendation": "Disable QuantumLock OR disable RPC + heartbeat on this secret — these are mutually exclusive per Delinea docs.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R5b",
        "name": "QuantumLock single-user lockout risk",
        "mode": 1,
        "category": "configuration",
        "conditions": [
            ("quantumlock_group_user_count", "==", 1),
            ("group_member_account_deleted", "==", True),
            ("no_recovery_path_available", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("quantumlock_lockout_risk", True),
        "recommendation": "Add at least 2 users to the QuantumLock group to prevent permanent data loss.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R6",
        "name": "Approval workflow required",
        "mode": 1,
        "category": "workflow",
        "conditions": [
            ("secret_requires_approval", "==", True),
            ("requester_role_not_in_approval_group", "==", True),
            ("no_active_approval", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("approval_workflow_required", True),
        "recommendation": "Submit request through approval workflow — secret requires approval before access.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R7",
        "name": "Two-person approval for break-glass access",
        "mode": 1,
        "category": "workflow",
        "conditions": [
            ("request_type", "==", "break_glass"),
            ("resource_sensitivity", "==", "high"),
            ("required_approvers", "<", 2),
            ("dual_control_not_enabled", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("two_person_approval_required", True),
        "recommendation": "Configure two-person approval (Dual Control + multi-approver workflow) for break-glass access to high-sensitivity resources.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R8",
        "name": "Session recording required for privileged sessions",
        "mode": 1,
        "category": "audit",
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
        "id": "R9",
        "name": "Credential rotation overdue",
        "mode": 1,
        "category": "lifecycle",
        "conditions": [
            ("secret_has_rotation_policy", "==", True),
            ("days_since_last_rotation", ">", "rotation_interval"),
            ("rpc_enabled", "==", True),
            ("last_rotation_status", "!=", "success"),
        ],
        "logic": "AND",
        "conclusion": ("rotation_overdue", True),
        "recommendation": "Re-run credential rotation — last rotation failed or never ran within the interval.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R10",
        "name": "Separation of Duties violation",
        "mode": 1,
        "category": "governance",
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
        "id": "R11",
        "name": "Time-bound access not configured",
        "mode": 1,
        "category": "lifecycle",
        "conditions": [
            ("secret_supports_checkout", "==", True),
            ("expiry_date_set", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("time_bound_access_not_configured", True),
        "recommendation": "Set an expiry date on this secret — indefinite access is not permitted for checkout-capable secrets.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R12",
        "name": "Break-glass audit violation",
        "mode": 1,
        "category": "audit",
        "conditions": [
            ("access_type", "==", "break_glass"),
            ("audit_logging_enabled", "==", False),
            ("force_checkin_used", "==", True),
            ("no_justification_recorded", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("break_glass_audit_violation", True),
        "recommendation": "Enable audit logging and require justification for break-glass access.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R12a",
        "name": "Event Pipeline infinite loop detection",
        "mode": 1,
        "category": "meta",
        "conditions": [
            ("event_pipeline_triggered_count", ">=", 5),
            ("within_time_window_minutes", "==", 5),
            ("trigger_type_repeats", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("ep_infinite_loop_detected", True),
        "recommendation": "Investigate circular logic in Event Pipelines — Delinea will auto-deactivate involved EPs.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R13",
        "name": "Network exposure violation for DMZ access",
        "mode": 1,
        "category": "network",
        "conditions": [
            ("target_zone", "in", ["DMZ", "internet_exposed"]),
            ("connection_originates_from_internal_network", "==", True),
            ("vpn_tunnel_active", "==", False),
            ("source_ip_in_allowed_range", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("network_exposure_violation", True),
        "recommendation": "Require VPN tunnel or IP allowlisting for access to DMZ/internet-exposed resources.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R14",
        "name": "Final access decision",
        "mode": 1,
        "category": "decision",
        "conditions": [
            ("eligible_for_evaluation", "==", False),
            ("least_privilege_violation", "==", True),
            ("mfa_required", "==", True),
            ("aal3_required", "==", True),
            ("quantumlock_rotation_conflict", "==", True),
            ("quantumlock_lockout_risk", "==", True),
            ("two_person_approval_required", "==", True),
            ("session_recording_required", "==", True),
            ("rotation_overdue", "==", True),
            ("sod_violation", "==", True),
            ("time_bound_access_not_configured", "==", True),
            ("break_glass_audit_violation", "==", True),
            ("ep_infinite_loop_detected", "==", True),
            ("network_exposure_violation", "==", True),
        ],
        "logic": "DECISION_MATRIX",
        "conclusion": ("final_decision", "<computed>"),
        "recommendation": "See fired rules above for specific remediation steps.",
        "severity": None,
    },

]

MODE_2_RULES = [
    {
        "id": "R15",
        "name": "IIS app pool stopped or crashing",
        "mode": 2,
        "category": "web_tier",
        "conditions": [
            ("secret_server_app_pool_start_mode", "!=", "AlwaysRunning"),
            ("app_pool_idle_timeout_minutes", "!=", 0),
            ("app_pool_recycling_regular_interval", "!=", 0),
            ("load_user_profile_enabled", "==", False),
        ],
        "logic": "OR",
        "conclusion": ("iis_app_pool_misconfigured", True),
        "recommendation": "Set Start Mode=AlwaysRunning, Idle Time-out=0, Regular Time Interval=0, and enable Load User Profile in IIS.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R16",
        "name": "IIS website not responding on 443",
        "mode": 2,
        "category": "web_tier",
        "conditions": [
            ("iis_https_binding_present", "==", False),
            ("ssl_certificate_valid", "==", False),
            ("iis_website_state", "!=", "Started"),
            ("port_443_listening", "==", False),
        ],
        "logic": "OR",
        "conclusion": ("iis_https_unreachable", True),
        "recommendation": "Verify IIS HTTPS binding, SSL certificate validity, website state, and port 443 listening.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R17",
        "name": "SQL Server unreachable on 1433",
        "mode": 2,
        "category": "database_tier",
        "conditions": [
            ("sql_server_service_running", "==", False),
            ("port_1433_reachable", "==", False),
            ("sql_tcp_enabled", "==", False),
            ("sql_browser_service_running", "==", False),
            ("named_pipes_enabled", "==", False),
            ("sql_nocount_property", "==", "on"),
        ],
        "logic": "OR",
        "conclusion": ("sql_unreachable", True),
        "recommendation": "Check SQL Server service, TCP/1433, SQL Browser, named pipes, and NOCOUNT setting.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R17a",
        "name": "SQL collation mismatch",
        "mode": 2,
        "category": "database_tier",
        "conditions": [
            ("sql_server_collation", "!=", "SQL_Latin1_General_CP1_CI_AS"),
            ("database_collation", "!=", "server_collation"),
        ],
        "logic": "OR",
        "conclusion": ("sql_collation_mismatch", True),
        "recommendation": "Rebuild the database with SQL_Latin1_General_CP1_CI_AS collation to avoid post-installation issues.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R18",
        "name": "SQL auth mode mismatch",
        "mode": 2,
        "category": "database_tier",
        "conditions": [
            ("sql_auth_mode", "!=", "mixed"),
            ("sql_login_for_service_account_missing", "==", True),
            ("service_account_not_in_db_owner_role", "==", True),
            ("sql_account_password_policy_enforced", "==", True),
        ],
        "logic": "OR",
        "conclusion": ("sql_auth_misconfigured", True),
        "recommendation": "Enable mixed mode, create SQL login for service account, grant db_owner, exempt from password policy.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R19",
        "name": "App/DB version mismatch",
        "mode": 2,
        "category": "upgrade",
        "conditions": [
            ("secret_server_app_version", "!=", "sql_database_schema_version"),
            ("app_vm_reverted_without_db_revert", "==", True),
            ("last_upgrade_attempt", "==", "failed"),
            ("db_owner_role_granted", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("app_db_version_mismatch", True),
        "recommendation": "Coordinated recovery required: enable maintenance mode, stop IIS site, restore DB from coordinated backup, restore app VM to matching version, reactivate license.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R20",
        "name": "VM-to-VM network unreachable",
        "mode": 2,
        "category": "network",
        "conditions": [
            ("source_vm_running", "==", True),
            ("destination_vm_running", "==", True),
            ("destination_vm_ip_reachable_from_source", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("vm_to_vm_network_failure", True),
        "recommendation": "Check virtual switch, port group, firewall rules, and IP configuration on both VMs.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R21",
        "name": "DNS resolution failure",
        "mode": 2,
        "category": "network",
        "conditions": [
            ("hostname_does_not_resolve_to_ip", "==", True),
            ("resolved_ip_does_not_match_expected", "==", True),
            ("dns_server_unreachable", "==", True),
            ("dns_zone_misconfigured", "==", True),
        ],
        "logic": "OR",
        "conclusion": ("dns_resolution_failure", True),
        "recommendation": "Check DNS server reachability, zone configuration, host file overrides, and DNS cache.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R22",
        "name": "AD bind credential invalid",
        "mode": 2,
        "category": "identity",
        "conditions": [
            ("ad_sync_secret_exists", "==", False),
            ("ad_sync_secret_credentials_invalid", "==", True),
            ("ad_sync_account_lacks_required_permissions", "==", True),
            ("domain_controller_reachable", "==", False),
            ("ad_domain_active_flag", "==", False),
        ],
        "logic": "OR",
        "conclusion": ("ad_bind_failed", True),
        "recommendation": "Verify sync secret exists, credentials valid, AD permissions sufficient, DC reachable, domain marked active.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R22a",
        "name": "AD credential cache fallback",
        "mode": 2,
        "category": "identity",
        "conditions": [
            ("domain_controller_reachable", "==", False),
            ("ad_credential_caching_enabled", "==", True),
            ("cached_credentials_age_days", "<=", 30),
            ("entered_password_hash_matches_cached_hash", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("ad_cache_login_granted", True),
        "recommendation": "Login granted via cached credentials. Restore domain controller access — cache expires in 30 days.",
        "severity": SEVERITY_LOW,
    },

    {
        "id": "R22b",
        "name": "AD sync safeguard triggered",
        "mode": 2,
        "category": "identity",
        "conditions": [
            ("ad_sync_returned_error", "==", True),
            ("ad_sync_returned_zero_users", "==", True),
            ("would_disable_all_users_in_domain", "==", True),
        ],
        "logic": "OR",
        "conclusion": ("ad_sync_safeguard_triggered", True),
        "recommendation": "Delinea safeguard prevented destructive sync. Investigate AD sync source before retrying.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R23",
        "name": "Heartbeat credential check failed",
        "mode": 2,
        "category": "heartbeat",
        "conditions": [
            ("heartbeat_enabled", "==", True),
            ("last_heartbeat_status", "==", "Failed"),
            ("target_machine_reachable", "==", True),
            ("credentials_valid_on_target", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("heartbeat_failed", True),
        "recommendation": "Credentials are out of sync. Trigger RPC rotation to update the stored credential.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R23a",
        "name": "DNS mismatch detected via heartbeat",
        "mode": 2,
        "category": "heartbeat",
        "conditions": [
            ("heartbeat_status", "==", "DnsMismatch"),
            ("target_hostname_resolves_to_unexpected_ip", "==", True),
            ("secret_stored_hostname", "!=", "resolved_ip"),
        ],
        "logic": "AND",
        "conclusion": ("dns_mismatch_detected", True),
        "recommendation": "Investigate DNS resolution, host file overrides, or potential DNS poisoning.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R23b",
        "name": "Authentication protocol mismatch",
        "mode": 2,
        "category": "heartbeat",
        "conditions": [
            ("heartbeat_status", "==", "AuthProtocolUnavailable"),
            ("target_os", "==", "windows"),
            ("ntlm_disabled_on_target", "==", True),
            ("account_not_in_domain", "==", True),
        ],
        "logic": "AND",
        "conclusion": ("auth_protocol_mismatch", True),
        "recommendation": "Use UPN form (user@domain.com), join target to domain, or review NTLM policies on the target.",
        "severity": SEVERITY_MEDIUM,
    },

    {
        "id": "R23c",
        "name": "ESXi heartbeat failure",
        "mode": 2,
        "category": "heartbeat",
        "conditions": [
            ("target_system_type", "==", "ESXi"),
            ("heartbeat_status", "==", "Failed"),
            ("root_credential_invalid", "==", True),
            ("esxi_host_unreachable", "==", False),
        ],
        "logic": "AND",
        "conclusion": ("esxi_root_credential_invalid", True),
        "recommendation": "Rotate root credential via vSphere, update Secret Server secret, re-run heartbeat.",
        "severity": SEVERITY_HIGH,
    },

    {
        "id": "R24",
        "name": "HA failover not occurring",
        "mode": 2,
        "category": "availability",
        "conditions": [
            ("primary_web_node_down", "==", True),
            ("traffic_not_redirected_to_secondary", "==", True),
            ("load_balancer_health_check_failing", "==", True),
        ],
        "logic": "OR",
        "conclusion": ("ha_failover_failure", True),
        "recommendation": "Check load balancer health check, cluster configuration, and secondary node status.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R24a",
        "name": "SQL Server mirroring / AlwaysOn failure",
        "mode": 2,
        "category": "availability",
        "conditions": [
            ("sql_alwayon_ag_state", "!=", "healthy"),
            ("sql_mirror_partner_unreachable", "==", True),
        ],
        "logic": "OR",
        "conclusion": ("sql_ha_failover_failure", True),
        "recommendation": "Check AlwaysOn AG state, mirror partner reachability, and automatic failover configuration.",
        "severity": SEVERITY_CRITICAL,
    },

    {
        "id": "R25",
        "name": "Recommended next diagnostic step",
        "mode": 2,
        "category": "decision",
        "conditions": [],  
        "logic": "PRIORITY_FIRST",
        "conclusion": ("next_step", "<computed>"),
        "recommendation": "See highest-severity fired rule above for specific action.",
        "severity": None,
    },

    {
        "id": "R26",
        "name": "Severity scoring",
        "mode": 2,
        "category": "decision",
        "conditions": [],  
        "logic": "PRIORITY_FIRST",
        "conclusion": ("severity", "<computed>"),
        "recommendation": "Severity assigned based on highest-severity fired rule.",
        "severity": None,
    },

]

ALL_RULES = MODE_1_RULES + MODE_2_RULES