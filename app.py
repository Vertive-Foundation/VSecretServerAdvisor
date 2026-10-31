import json
from datetime import datetime
import streamlit as st
from knowledge_base import ALL_RULES
from inference_engine import evaluate
from utils import (MODE_1_DEFAULTS, MODE_2_DEFAULTS, MODE_1_PRESETS, MODE_2_PRESETS,
    MODE_1_SECTIONS, MODE_2_SECTIONS, FACT_LABELS, get_default_facts, apply_preset, get_section_modified_map)

st.set_page_config(
    page_title="VSecretServerAdvisor",   
    page_icon="static/favicon.png",     
    layout="wide",                       
    initial_sidebar_state="collapsed",    
)

CUSTOM_CSS = """
<style>
    /* Hide the sidebar — we navigate via the welcome screen buttons */
    [data-testid="stSidebar"] { display: none !important; }

    /* Center the welcome screen content */
    .welcome-container {
        text-align: center;
        padding: 4rem 1rem 2rem 1rem;
    }
    .welcome-container h1 {
        font-size: 3rem !important;
        font-weight: 700 !important;
        color: #1B3A57 !important;
        margin-bottom: 0.5rem !important;
    }
    .welcome-container h2 {
        font-size: 1.25rem !important;
        font-weight: 400 !important;
        color: #6B7280 !important;
        margin-bottom: 3rem !important;
    }
    .welcome-buttons {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
        max-width: 360px;
        margin: 0 auto;
    }

    /* Logo placeholder — large shield emoji above the title */
    .logo-placeholder {
        font-size: 80px;
        margin-bottom: 1rem;
    }

    /* Back button — subtle, top-left of each page */
    .back-button button {
        background: transparent !important;
        border: 1px solid #D1D5DB !important;
        color: #4B5563 !important;
        font-size: 0.9rem !important;
        padding: 0.4rem 0.9rem !important;
    }
    .back-button button:hover {
        background: #F3F4F6 !important;
        border-color: #9CA3AF !important;
    }

    /* Decision banner — Mode 1 (approve/deny/escalate) */
    .decision-banner {
        padding: 1.5rem 2rem;
        border-radius: 6px;
        margin: 1rem 0 1.5rem 0;
        text-align: center;
    }
    .decision-banner h2 {
        color: white !important;
        font-size: 1.75rem !important;
        font-weight: 700 !important;
        margin: 0 0 0.25rem 0 !important;
    }
    .decision-banner p {
        color: rgba(255, 255, 255, 0.9) !important;
        font-size: 0.95rem !important;
        margin: 0 !important;
    }
    .decision-approve { background: #059669; }
    .decision-deny { background: #DC2626; }
    .decision-escalate { background: #D97706; }

    /* Severity banner — Mode 2 (critical/high/medium/low/info) */
    .severity-banner {
        padding: 1.5rem 2rem;
        border-radius: 6px;
        margin: 1rem 0 1.5rem 0;
    }
    .severity-banner h2 {
        color: white !important;
        font-size: 1.4rem !important;
        font-weight: 700 !important;
        margin: 0 0 0.25rem 0 !important;
    }
    .severity-banner p {
        color: rgba(255, 255, 255, 0.9) !important;
        font-size: 0.95rem !important;
        margin: 0 !important;
    }
    .severity-critical { background: #991B1B; }
    .severity-high { background: #C2410C; }
    .severity-medium { background: #B45309; }
    .severity-low { background: #1E40AF; }
    .severity-info { background: #4B5563; }

    /* === Trace entries === */
    .trace-entry {
    border-left: 3px solid #E5E7EB;
    padding: 0.6rem 0 0.6rem 1rem;
    margin-bottom: 0.75rem;
    font-size: 0.9rem;
    line-height: 1.5;
    color: #1F2937;              /* main text — dark slate, high contrast */
    }
    .trace-fired {
    border-left-color: #059669;  /* green left border */
    background: #F0FDF4;          /* faint green tint behind fired entries */
    border-radius: 0 4px 4px 0;
    }
    .trace-fired strong {
    color: #047857;               /* fired rule name — dark green */
    }
    .trace-fired em {
    color: #065F46;               /* recommendation italic — darker green */
    }
    .trace-not-fired {
    border-left-color: #D1D5DB;
    color: #6B7280;               /* muted gray text */
    background: #F9FAFB;          /* very faint gray tint */
    border-radius: 0 4px 4px 0;
    }
    .trace-not-fired strong {
    color: #9CA3AF;               /* lighter gray for not-fired rule names */
    }

    .footer {
        margin-top: 4rem;
        padding-top: 1.5rem;
        border-top: 1px solid #E5E7EB;
        text-align: center;
        color: #6B7280;
        font-size: 0.85rem;
    }
    .footer a {
        color: #6B7280;
        text-decoration: none;
    }
    .footer a:hover {
        color: #1B3A57;
        text-decoration: underline;
    }

    .section-modified-tag {
        color: #B45309;
        font-size: 0.8rem;
        font-weight: 500;
        margin-left: 0.5rem;
    }

    .recommendation-list {
        background: #F9FAFB;
        border-left: 3px solid #1B3A57;
        padding: 1rem 1.25rem;
        margin: 1rem 0;
        border-radius: 0 4px 4px 0;
    }
    .recommendation-list h4 {
        margin: 0 0 0.5rem 0 !important;
        color: #1B3A57 !important;
        font-size: 1rem !important;
    }
    .recommendation-list ul {
        margin: 0 !important;
        padding-left: 1.2rem !important;
    }
    .recommendation-list li {
        margin-bottom: 0.4rem;
        color: #1F2937; 
    }

    .evidence-list {
        background: #FEF3C7;
        border: 1px solid #FCD34D;
        padding: 1rem 1.25rem;
        margin: 1rem 0;
        border-radius: 4px;
    }
    .evidence-list h4 {
        margin: 0 0 0.5rem 0 !important;
        color: #92400E !important;
        font-size: 0.95rem !important;
    }
    .evidence-list ul {
        margin: 0 !important;
        padding-left: 1.2rem !important;
    }
    .evidence-list li {
        margin-bottom: 0.3rem;
        color: #78350F; 
    }

    .page-title {
        color: #1B3A57;
        font-size: 1.75rem !important;
        font-weight: 600 !important;
        margin-bottom: 0.25rem !important;
    }
    .page-subtitle {
        color: #6B7280;
        font-size: 1rem !important;
        margin-bottom: 1.5rem !important;
    }
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

def init_session_state():
    if "page" not in st.session_state:
        st.session_state.page = "home"

    for fact_key, default_value in MODE_1_DEFAULTS.items():
        widget_key = f"m1_{fact_key}"
        if widget_key not in st.session_state:
            st.session_state[widget_key] = default_value

    for fact_key, default_value in MODE_2_DEFAULTS.items():
        widget_key = f"m2_{fact_key}"
        if widget_key not in st.session_state:
            st.session_state[widget_key] = default_value

    if "m1_result" not in st.session_state:
        st.session_state.m1_result = None
    if "m2_result" not in st.session_state:
        st.session_state.m2_result = None

def go_to(page):
    st.session_state.page = page
    st.rerun()

def go_home():
    st.session_state.page = "home"
    st.rerun()

def collect_facts(mode):
    defaults = MODE_1_DEFAULTS if mode == 1 else MODE_2_DEFAULTS
    prefix = "m1_" if mode == 1 else "m2_"
    return {
        fact_key: st.session_state[f"{prefix}{fact_key}"]
        for fact_key in defaults
    }


def load_preset_into_session(mode, preset_index):
    facts = apply_preset(mode, preset_index)
    prefix = "m1_" if mode == 1 else "m2_"
    for fact_key, value in facts.items():
        st.session_state[f"{prefix}{fact_key}"] = value
    if mode == 1:
        st.session_state.m1_result = None
    else:
        st.session_state.m2_result = None


def render_home():
    col1, col2, col3 = st.columns([3, 1, 3])
    with col2:
        st.image("static/logo.png", width=200)

    st.markdown("""
    <div class="welcome-container" style="padding-top: 0rem;">
        <h1>VSecretServerAdvisor</h1>
        <h2>Secret Server Expert System</h2>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("Access Evaluator", use_container_width=True, key="go_mode1"):
            go_to("mode1")
        if st.button("Incident Diagnostician", use_container_width=True, key="go_mode2"):
            go_to("mode2")
        if st.button("About", use_container_width=True, key="go_about"):
            go_to("about")

    render_footer()


def render_mode_1():
    if st.button("← Back", key="back_from_m1"):
        go_home()

    st.markdown('<h1 class="page-title">Access Evaluator</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Evaluates whether a privileged access request should be approved, denied, or escalated.</p>', unsafe_allow_html=True)
    st.markdown("#### Common scenarios")
    st.markdown("<p style='font-size: 0.9rem; color: #6B7280; margin-top: -0.5rem; margin-bottom: 1rem;'>Click a scenario to pre-fill the form, then press Evaluate.</p>", unsafe_allow_html=True)

    preset_cols = st.columns(len(MODE_1_PRESETS))
    for i, preset in enumerate(MODE_1_PRESETS):
        with preset_cols[i]:
            if st.button(preset["name"], key=f"m1_preset_{i}", use_container_width=True):
                load_preset_into_session(1, i)
                st.rerun()

    st.markdown("---")

    current_facts = collect_facts(1)
    modified_map = get_section_modified_map(1, current_facts)

    st.markdown("#### Request details")
    st.markdown("<p style='font-size: 0.9rem; color: #6B7280; margin-top: -0.5rem; margin-bottom: 1rem;'>Expand each section to modify the request parameters.</p>", unsafe_allow_html=True)

    render_mode_1_form(modified_map)

    st.markdown("---")
    if st.button("Evaluate Request", type="primary", use_container_width=True, key="m1_evaluate"):
        facts = collect_facts(1)
        result = evaluate(ALL_RULES, facts, mode=1)
        st.session_state.m1_result = result
        st.rerun()

    if st.session_state.m1_result is not None:
        render_mode_1_result(st.session_state.m1_result)

    render_footer()


def render_mode_2():
    if st.button("← Back", key="back_from_m2"):
        go_home()

    st.markdown('<h1 class="page-title">Incident Diagnostician</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Diagnoses what is wrong when Secret Server or its dependencies (IIS, SQL, AD, network) misbehave.</p>', unsafe_allow_html=True)
    st.markdown("#### Common incidents")
    st.markdown("<p style='font-size: 0.9rem; color: #6B7280; margin-top: -0.5rem; margin-bottom: 1rem;'>Click an incident pattern to pre-fill the form, then press Diagnose.</p>", unsafe_allow_html=True)

    preset_cols_1 = st.columns(4)
    preset_cols_2 = st.columns(3)
    all_cols = list(preset_cols_1) + list(preset_cols_2)

    for i, preset in enumerate(MODE_2_PRESETS):
        with all_cols[i]:
            if st.button(preset["name"], key=f"m2_preset_{i}", use_container_width=True):
                load_preset_into_session(2, i)
                st.rerun()

    st.markdown("---")

    current_facts = collect_facts(2)
    modified_map = get_section_modified_map(2, current_facts)

    st.markdown("#### System observations")
    st.markdown("<p style='font-size: 0.9rem; color: #6B7280; margin-top: -0.5rem; margin-bottom: 1rem;'>Expand each section to record what you observed. Modified sections are marked and auto-expanded.</p>", unsafe_allow_html=True)

    render_mode_2_form(modified_map)

    st.markdown("---")
    if st.button("Diagnose", type="primary", use_container_width=True, key="m2_diagnose"):
        facts = collect_facts(2)
        result = evaluate(ALL_RULES, facts, mode=2)
        st.session_state.m2_result = result
        st.rerun()

    if st.session_state.m2_result is not None:
        render_mode_2_result(st.session_state.m2_result)

    render_footer()


def render_about():
    if st.button("← Back", key="back_from_about"):
        go_home()

    st.markdown('<h1 class="page-title">About VSecretServerAdvisor</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Secret Server Expert System</p>', unsafe_allow_html=True)

    st.markdown("""
    ## What is VSecretServerAdvisor?

    VSecretServerAdvisor is a rule-based expert system that emulates the decision-making
    of a Privileged Access Management (PAM) administrator for Delinea Secret Server.

    It runs in two modes:

    - **Access Evaluator** — Evaluates whether a privileged access request should be
      approved, denied, or escalated. The system applies 17 rules covering eligibility,
      authentication, separation of duties, workflow, session recording, and other
      access-control concerns.

    - **Incident Diagnostician** — Diagnoses what is wrong when Secret Server or its
      infrastructure dependencies (IIS, SQL Server, Active Directory, network) misbehave.
      The system applies 19 rules covering web tier, database tier, network, identity,
      heartbeat, and high-availability failures.

    ## What is Secret Server?

    Delinea Secret Server is a Privileged Access Management (PAM) platform. It stores
    privileged credentials (administrator passwords, root accounts, service account
    credentials) in an encrypted vault and controls who can access them, when, and
    under what conditions.

    PAM systems like Secret Server are deployed by organizations to:

    - Reduce the risk of credential theft or misuse
    - Enforce least-privilege access to sensitive systems
    - Provide an audit trail of privileged activity
    - Automate credential rotation and lifecycle management

    ## How does VSecretServerAdvisor work?

    The system follows the classic expert-system architecture:

    1. **Knowledge Base** (`knowledge_base.py`) — Contains 36 rules encoded as
       IF-THEN statements. Each rule has conditions (the IF part) and a conclusion
       (the THEN part), plus a recommendation for the user.

    2. **Inference Engine** (`inference_engine.py`) — A forward-chaining rule
       engine. It takes the rules and a set of facts (provided by the user via the
       UI), applies the rules, and derives conclusions. It also produces a trace
       that explains which rules fired and why.

    3. **User Interface** (`app.py`) — A Streamlit web app that lets the user
       describe a request (Mode 1) or system observations (Mode 2) and displays
       the system's conclusion with a full explanation.

    ## Rule count and condition count

    - **36 rules** across both modes (17 in Mode 1, 19 in Mode 2)
    - **126 condition tests** across all rules
    - Rules are sourced from Delinea Secret Server documentation and from
      NIST SP 800-53 and NIST SP 800-63B security controls.
    """)

    render_footer()


def render_mode_1_form(modified_map):
    for section_idx, (section_name, fact_keys) in enumerate(MODE_1_SECTIONS):
        modified = modified_map[section_idx]
        header = f"{section_name}{' · modified' if modified else ''}"

        with st.expander(header, expanded=modified):
            cols = st.columns(2)
            for i, fact_key in enumerate(fact_keys):
                with cols[i % 2]:
                    render_widget_for_fact(fact_key, "m1_")


def render_mode_2_form(modified_map):
    for section_idx, (section_name, fact_keys) in enumerate(MODE_2_SECTIONS):
        modified = modified_map[section_idx]
        header = f"{section_name}{' · modified' if modified else ''}"

        with st.expander(header, expanded=modified):
            cols = st.columns(2)
            for i, fact_key in enumerate(fact_keys):
                with cols[i % 2]:
                    render_widget_for_fact(fact_key, "m2_")


def render_widget_for_fact(fact_key, prefix):
    widget_key = f"{prefix}{fact_key}"
    label = FACT_LABELS.get(fact_key, fact_key.replace("_", " ").title())

    if prefix == "m1_":
        default = MODE_1_DEFAULTS[fact_key]
    else:
        default = MODE_2_DEFAULTS[fact_key]

    enum_options = {
        "account_type": ["standard", "privileged"],
        "mfa_assurance_level": ["none", "AAL1", "AAL2", "AAL3"],
        "resource_sensitivity": ["low", "medium", "high", "critical"],
        "requested_privilege_level": ["view", "edit", "own", "admin"],
        "target_zone": ["internal", "DMZ", "internet_exposed"],
        "request_type": ["standard", "break_glass"],
        "session_type": ["standard", "privileged"],
        "access_type": ["standard", "break_glass"],
        "last_rotation_status": ["success", "failed", "never_run"],

        "secret_server_app_pool_start_mode": ["AlwaysRunning", "OnDemand", "Stopped"],
        "iis_website_state": ["Started", "Stopped"],
        "sql_nocount_property": ["on", "off"],
        "sql_auth_mode": ["mixed", "windows_only"],
        "last_upgrade_attempt": ["success", "failed", "never"],
        "heartbeat_status": ["Success", "Failed", "UnableToConnect", "DnsMismatch",
                              "AuthProtocolUnavailable", "AccountLockedOut", "Disabled"],
        "last_heartbeat_status": ["Success", "Failed", "UnableToConnect", "DnsMismatch",
                                   "AuthProtocolUnavailable", "AccountLockedOut", "Disabled"],
        "target_os": ["windows", "linux", "ESXi"],
        "target_system_type": ["Windows", "Linux", "ESXi"],
        "sql_alwayon_ag_state": ["healthy", "unhealthy", "unknown"],
    }

    if isinstance(default, bool):
        st.toggle(label, key=widget_key)
    elif isinstance(default, int):
        st.number_input(label, key=widget_key, step=1)
    elif isinstance(default, str):
        if fact_key in enum_options:
            options = enum_options[fact_key]
            st.selectbox(label, options=options, key=widget_key)
        else:
            st.text_input(label, key=widget_key)
    else:
        st.text_input(label, key=widget_key)

def render_mode_1_result(result):
    if result.get("error"):
        st.error(f"Engine error: {result['error']}")
        return

    decision = result.get("decision", "unknown")
    trace = result.get("trace", [])
    fired_entries = [e for e in trace if e.get("fired")]
    fired_count = len(fired_entries)

    severities = [e.get("severity") for e in fired_entries if e.get("severity")]
    if severities:
        severity_order = ["info", "low", "medium", "high", "critical"]
        max_severity = max(severities, key=lambda s: severity_order.index(s) if s in severity_order else 0)
    else:
        max_severity = "info"

    banner_class = {
        "approve": "decision-approve",
        "deny": "decision-deny",
        "escalate": "decision-escalate",
    }.get(decision, "decision-deny")

    banner_text = {
        "approve": "✓ APPROVED",
        "deny": "✗ DENIED",
        "escalate": "↑ ESCALATED",
    }.get(decision, decision.upper())

    summary = f"{fired_count} rule(s) fired · severity: {max_severity}"

    st.markdown(f"""
    <div class="decision-banner {banner_class}">
        <h2>{banner_text}</h2>
        <p>{summary}</p>
    </div>
    """, unsafe_allow_html=True)

    if fired_entries:
        recommendations_html = "<ul>"
        for entry in fired_entries:
            if entry.get("rule_id") == "R14":
                continue
            recommendations_html += f"<li>{entry['recommendation']}</li>"
        recommendations_html += "</ul>"

        st.markdown(f"""
        <div class="recommendation-list">
            <h4>Recommendations</h4>
            {recommendations_html}
        </div>
        """, unsafe_allow_html=True)

    with st.expander("Show detailed reasoning", expanded=False):
        render_trace(trace, mode=1)

    render_download_button(trace, decision, mode=1)


def render_mode_2_result(result):
    if result.get("error"):
        st.error(f"Engine error: {result['error']}")
        return

    decision = result.get("decision", {})
    severity = decision.get("severity", "info")
    next_step = decision.get("next_step", "No incidents detected.")
    primary_rule_id = decision.get("primary_diagnosis_rule_id")

    trace = result.get("trace", [])
    fired_entries = [e for e in trace if e.get("fired")]
    banner_class = f"severity-{severity}"
    severity_label = severity.upper()

    primary_rule_name = "No specific incident"
    if primary_rule_id:
        for e in fired_entries:
            if e.get("rule_id") == primary_rule_id:
                primary_rule_name = e.get("rule_name", primary_rule_id)
                break

    st.markdown(f"""
    <div class="severity-banner {banner_class}">
        <h2>{severity_label} · {primary_rule_name}</h2>
        <p>Primary diagnosis based on observed conditions</p>
    </div>
    """, unsafe_allow_html=True)

    if primary_rule_id:
        primary_entry = next((e for e in fired_entries if e.get("rule_id") == primary_rule_id), None)
        if primary_entry:
            evidence_html = "<ul>"
            for cond in primary_entry.get("conditions", []):
                if cond.get("matched"):
                    fact_label = FACT_LABELS.get(cond["fact_key"], cond["fact_key"])
                    actual = cond.get("actual_value")
                    expected = cond.get("expected_value")
                    if cond["operator"] == "in":
                        evidence_html += f"<li><strong>{fact_label}</strong> is <code>{actual}</code> (one of {expected})</li>"
                    elif cond["operator"] in ("==", "!="):
                        evidence_html += f"<li><strong>{fact_label}</strong>: <code>{actual}</code></li>"
                    else:
                        evidence_html += f"<li><strong>{fact_label}</strong>: <code>{actual}</code> (expected {cond['operator']} {expected})</li>"
            evidence_html += "</ul>"

            st.markdown(f"""
            <div class="evidence-list">
                <h4>Evidence — conditions that matched</h4>
                {evidence_html}
            </div>
            """, unsafe_allow_html=True)

    st.markdown("#### Recommended action")
    st.markdown(next_step)

    with st.expander("Show full reasoning trace", expanded=False):
        render_trace(trace, mode=2)

    render_download_button(trace, decision, mode=2)

def render_trace(trace, mode):
    fired = [e for e in trace if e.get("fired")]
    not_fired = [e for e in trace if not e.get("fired")]

    if fired:
        st.markdown(f"**Rules that fired ({len(fired)}):**")
        for entry in fired:
            render_trace_entry_fired(entry)
    else:
        st.markdown("**No rules fired.** All conditions are within safe parameters.")

    if not_fired:
        with st.expander(f"Why didn't other rules fire? ({len(not_fired)} checked)"):
            for entry in not_fired:
                render_trace_entry_not_fired(entry)


def render_trace_entry_fired(entry):
    rule_id = entry.get("rule_id", "?")
    rule_name = entry.get("rule_name", "")
    recommendation = entry.get("recommendation", "")

    matched_conds = [c for c in entry.get("conditions", []) if c.get("matched")]
    cond_lines = []
    for c in matched_conds:
        fact_label = FACT_LABELS.get(c["fact_key"], c["fact_key"])
        actual = c.get("actual_value")
        if c["operator"] == "==":
            cond_lines.append(f"• {fact_label}: {actual}")
        elif c["operator"] == "!=":
            cond_lines.append(f"• {fact_label}: {actual} (expected to differ from {c['expected_value']})")
        elif c["operator"] == "in":
            cond_lines.append(f"• {fact_label}: {actual} (one of {c['expected_value']})")
        else:
            cond_lines.append(f"• {fact_label}: {actual} ({c['operator']} {c['expected_value']})")

    conditions_text = "<br>".join(cond_lines) if cond_lines else "• (no explicit conditions — synthesis rule)"

    if entry.get("logic") in ("DECISION_MATRIX", "PRIORITY_FIRST"):
        st.markdown(f"""
        <div class="trace-entry trace-fired">
            <strong>✓ {rule_name}</strong> ({rule_id})<br>
            <em>{recommendation}</em>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="trace-entry trace-fired">
            <strong>✓ {rule_name}</strong> ({rule_id})<br>
            Matched conditions:<br>
            {conditions_text}<br>
            <em>→ {recommendation}</em>
        </div>
        """, unsafe_allow_html=True)


def render_trace_entry_not_fired(entry):
    rule_id = entry.get("rule_id", "?")
    rule_name = entry.get("rule_name", "")
    logic = entry.get("logic", "AND")

    failed_conds = [c for c in entry.get("conditions", []) if not c.get("matched")]
    if failed_conds:
        first_failed = failed_conds[0]
        fact_label = FACT_LABELS.get(first_failed["fact_key"], first_failed["fact_key"])
        actual = first_failed.get("actual_value")
        expected = first_failed.get("expected_value")

        if first_failed.get("fact_missing"):
            reason = f"{fact_label} was not provided"
        elif logic == "AND":
            reason = f"{fact_label}: {actual} (expected {first_failed['operator']} {expected})"
        else:  # OR
            reason = f"none of the conditions matched (first checked: {fact_label}: {actual})"
    else:
        reason = "all conditions matched but rule still did not fire (unexpected)"

    st.markdown(f"""
    <div class="trace-entry trace-not-fired">
        <strong>✗ {rule_name}</strong> ({rule_id}) — {reason}
    </div>
    """, unsafe_allow_html=True)


def render_download_button(trace, decision, mode):
    export_data = {
        "timestamp": datetime.now().isoformat(),
        "mode": mode,
        "decision": decision,
        "trace": [
            {
                "rule_id": e.get("rule_id"),
                "rule_name": e.get("rule_name"),
                "fired": e.get("fired"),
                "conditions": e.get("conditions", []),
                "recommendation": e.get("recommendation"),
                "severity": e.get("severity"),
            }
            for e in trace
        ],
    }

    json_str = json.dumps(export_data, indent=2, default=str)
    st.download_button(
        label="Download trace (JSON)",
        data=json_str,
        file_name=f"vsecretserveradvisor_trace_{mode}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
    )

def render_footer():
    github_url = "GITHUB_URL" 

    st.markdown(f"""
    <div class="footer">
        © {datetime.now().year} VSecretServerAdvisor ·
        <a href="{github_url}" target="_blank">Source code</a>
    </div>
    """, unsafe_allow_html=True)


def main():
    init_session_state()

    page = st.session_state.page
    if page == "home":
        render_home()
    elif page == "mode1":
        render_mode_1()
    elif page == "mode2":
        render_mode_2()
    elif page == "about":
        render_about()
    else:
        st.session_state.page = "home"
        st.rerun()

if __name__ == "__main__":
    main()