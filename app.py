import json
from datetime import datetime
from pathlib import Path

import streamlit as st

from knowledge_base import ALL_RULES
from inference_engine import evaluate, STATUS_CONFIRMED, STATUS_POSSIBLE
from utils import (
    MODE_1_DEFAULTS, MODE_2_DEFAULTS,
    MODE_1_PRESETS, MODE_2_PRESETS,
    MODE_1_SECTIONS, MODE_2_SECTIONS,
    FACT_LABELS, apply_preset,
)
from fact_validator import find_conflicts, find_stale_answers

GITHUB_URL = "https://github.com/Vertive-Foundation/VSecretServerAdvisor"

STATIC_DIR = Path(__file__).parent / "static"
FAVICON = STATIC_DIR / "favicon.png"
LOGO = STATIC_DIR / "logo.png"

st.set_page_config(
    page_title="VSecretServerAdvisor",
    page_icon=str(FAVICON) if FAVICON.exists() else "🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

UNKNOWN = "__unknown__"
SYNTHESIS_LOGICS = ("DECISION_MATRIX", "PRIORITY_FIRST")
MODE_NAMES = {1: "Access Evaluator", 2: "Incident Diagnostician"}
NOT_CONSIDERED = "not_considered"

CORE_SECTION_NAME = "Requester & Authentication"
ALL_SECTIONS_MODE1 = [name for name, _ in MODE_1_SECTIONS]
EXTRA_SECTIONS_MODE1 = [name for name in ALL_SECTIONS_MODE1 if name != CORE_SECTION_NAME]

HARD_STOP_FACTS = {
    "account_active": "Account is not active",
    "account_not_locked": "Account is locked",
}

SECRET_SIDE_SECTIONS = ["Secret Configuration", "Credential Lifecycle",
                        "QuantumLock Risk", "Event Pipeline"]

INTRO_MODE1 = (
    "I evaluate privileged access requests against Secret Server policy."
)

INTRO = {
    1: INTRO_MODE1,
    2: ("I diagnose Secret Server incidents. Choose the areas that seem to be misbehaving. "
        "Anything skipped or marked Not sure is listed as not considered."),
}

ENUM_OPTIONS = {
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

BRANCHES_MODE2 = {name: [name] for name, _ in MODE_2_SECTIONS}

DEPENDS = {
    "mfa_enabled": ("account_type", "privileged"),
    "mfa_assurance_level": ("account_type", "privileged"),
    "requester_role_not_authorized_for_high_sensitivity": ("resource_sensitivity", "high"),
    "task_can_be_completed_with_lower_privilege": ("requested_privileges_exceed_minimum", True),
    "requester_role_not_in_approval_group": ("secret_requires_approval", True),
    "no_active_approval": ("secret_requires_approval", True),
    "required_approvers": ("request_type", "break_glass"),
    "session_recording_enabled": ("session_type", "privileged"),
    "checkout_duration_hours": ("secret_supports_checkout", True),
    "expiry_date_set": ("secret_supports_checkout", True),
    "days_since_last_rotation": ("secret_has_rotation_policy", True),
    "rotation_interval": ("secret_has_rotation_policy", True),
    "last_rotation_status": ("secret_has_rotation_policy", True),
    "quantumlock_group_user_count": ("secret_has_quantumlock_enabled", True),
    "group_member_account_deleted": ("secret_has_quantumlock_enabled", True),
    "no_recovery_path_available": ("secret_has_quantumlock_enabled", True),
    "quantumlock_password_forgotten": ("quantumlock_group_user_count", 1),
    "cached_credentials_age_days": ("ad_credential_caching_enabled", True),
    "entered_password_hash_matches_cached_hash": ("ad_credential_caching_enabled", True),
}


def defaults_for(mode):
    return MODE_1_DEFAULTS if mode == 1 else MODE_2_DEFAULTS


def sections_for(mode):
    return MODE_1_SECTIONS if mode == 1 else MODE_2_SECTIONS


def label_of(key):
    return FACT_LABELS.get(key, key.replace("_", " ").capitalize())


def conclusion_names(mode):
    return {r["conclusion"][0]: r["name"] for r in ALL_RULES
            if r["mode"] == mode and r["logic"] not in SYNTHESIS_LOGICS}


def missing_label(mode, key):
    if key in FACT_LABELS:
        return FACT_LABELS[key]
    return conclusion_names(mode).get(key, label_of(key))


def show_value(value):
    if value == UNKNOWN:
        return "Not sure (not considered)"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def fmt(value):
    if isinstance(value, dict) and "ref" in value:
        return f"'{label_of(value['ref'])}'"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, str) and value in FACT_LABELS:
        return f"'{FACT_LABELS[value]}'"
    return str(value)


def fact_kind(mode, key):
    if key in ENUM_OPTIONS:
        return "choice"
    default = defaults_for(mode)[key]
    if isinstance(default, bool):
        return "bool"
    if isinstance(default, (int, float)):
        return "number"
    return "text"


def fact_order(mode):
    order = []
    for _, keys in sections_for(mode):
        for k in keys:
            if k not in order:
                order.append(k)
    for k in defaults_for(mode):
        if k not in order:
            order.append(k)
    return order


def branch_of(key):
    for name, keys in MODE_2_SECTIONS:
        if key in keys:
            return name
    return None


def section_of(mode, key):
    for name, keys in sections_for(mode):
        if key in keys:
            return name
    return None


def allowed_facts(branches):
    if branches is None:
        return set(MODE_2_DEFAULTS)
    wanted = set()
    for b in branches:
        wanted.update(BRANCHES_MODE2[b])
    allowed = set()
    for name, keys in MODE_2_SECTIONS:
        if name in wanted:
            allowed.update(keys)
    return allowed


def allowed_for(mode):
    ss = st.session_state
    if mode == 1:
        return ss.scope_facts
    areas = list(ss.branches or []) + [a for a in (ss.skipped_areas or [])
                                        if a not in (ss.branches or [])]
    return allowed_facts(areas or None)


def announce_next_area(previous_section):
    ss = st.session_state
    key = next_question(2, ss.answers, ss.branches)
    if key is None:
        return
    section = section_of(2, key)
    if section is None or section == previous_section:
        return
    if previous_section is None:
        text = f"Asking questions about {section}."
    else:
        text = f"Now asking questions about {section}."
    ss.messages.append(("assistant", text))


def in_scope_rules(mode, allowed):
    rules = [r for r in ALL_RULES if r["mode"] == mode]
    if allowed is None:
        return rules
    defaults = defaults_for(mode)
    by_conclusion = {r["conclusion"][0]: r for r in rules if r["logic"] not in SYNTHESIS_LOGICS}
    cache = {}

    def touches_outside(rule):
        rid = rule["id"]
        if rid in cache:
            return cache[rid]
        cache[rid] = False
        hit = False
        for fk, _, exp in rule.get("conditions", []):
            keys = [fk]
            if isinstance(exp, dict) and "ref" in exp:
                keys.append(exp["ref"])
            for k in keys:
                if k in by_conclusion and touches_outside(by_conclusion[k]):
                    hit = True
                elif k in defaults and k not in allowed:
                    hit = True
        cache[rid] = hit
        return hit

    return [r for r in rules if not touches_outside(r)]


def dependency_status(mode, key, answers):
    if key not in DEPENDS:
        return True, None
    parent, required = DEPENDS[key]
    if parent not in answers:
        return False, f"waits on '{label_of(parent)}', which was not asked"
    value = answers[parent]
    if value == UNKNOWN:
        return False, f"'{label_of(parent)}' was marked Not sure, so this question was not asked"
    if value != required:
        return False, f"only relevant when '{label_of(parent)}' is {show_value(required)}"
    return dependency_status(mode, parent, answers)


def next_question(mode, answers, branches):
    allowed = allowed_facts(branches)
    for key in fact_order(mode):
        if key in answers or key not in allowed:
            continue
        ok, _ = dependency_status(mode, key, answers)
        if ok:
            return key
    return None


def skipped_report(mode, answers, allowed, skipped_areas=()):
    if allowed is None:
        allowed = set(defaults_for(mode))
    rows = []
    for key in fact_order(mode):
        if key in answers and answers[key] != UNKNOWN:
            continue
        area = branch_of(key) if mode == 2 else None
        if area in (skipped_areas or ()):
            reason = "you skipped this area, so nothing in it was checked"
        elif key not in allowed:
            reason = "this area was not selected, so it was not checked"
        elif answers.get(key) == UNKNOWN:
            reason = "you answered Not sure, so the checks that use it were not considered"
        else:
            ok, why = dependency_status(mode, key, answers)
            reason = ("not answered, so the checks that depend on it were not considered"
                      if ok else why)
        rows.append((label_of(key), reason))
    return rows


def build_facts(answers):
    return {k: v for k, v in answers.items() if v != UNKNOWN}


def mode_rules(mode):
    return [r for r in ALL_RULES if r["mode"] == mode and r["logic"] not in SYNTHESIS_LOGICS]


def rule_depths(mode):
    rules = mode_rules(mode)
    by_id = {r["id"]: r for r in rules}
    producer = {r["conclusion"][0]: r["id"] for r in rules}
    depth = {}

    def walk(rid, seen):
        if rid in depth:
            return depth[rid]
        if rid in seen:
            return 1
        d = 1
        for cond in by_id[rid]["conditions"]:
            src = producer.get(cond[0])
            if src and src != rid:
                d = max(d, walk(src, seen | {rid}) + 1)
        depth[rid] = d
        return d

    for rid in by_id:
        walk(rid, frozenset())
    return depth


def describe_condition(c, mode):
    if c.get("unknown"):
        needs = ", ".join(missing_label(mode, m) for m in c.get("missing", []))
        return f"{needs or label_of(c['fact_key'])}: not answered"
    label = missing_label(mode, c["fact_key"])
    actual = fmt(c["actual_value"])
    op = c["operator"]
    exp = c["expected_value"]
    if op == "==":
        return f"{label} is {actual}"
    if op == "!=":
        return f"{label} is {actual} (not {fmt(exp)})"
    if op == "in":
        return f"{label} is {actual} (one of {', '.join(map(str, exp))})"
    if op == "not_in":
        return f"{label} is {actual} (not one of {', '.join(map(str, exp))})"
    return f"{label} is {actual} (needs {op} {fmt(exp)})"


def why_not(entry, mode):
    if entry.get("status") == NOT_CONSIDERED:
        needs = sorted({m for c in entry.get("conditions", []) for m in c.get("missing", [])})
        waiting = ", ".join(missing_label(mode, m) for m in needs) or "unanswered inputs"
        return f"not considered, waiting on {waiting}"
    failed = [c for c in entry.get("conditions", []) if not c["matched"] and not c.get("unknown")]
    if entry.get("logic") == "OR" or not failed:
        return "none of its conditions held"
    return describe_condition(failed[0], mode)


def mode1_rules():
    return [r for r in ALL_RULES if r["mode"] == 1 and r["logic"] not in SYNTHESIS_LOGICS]


def mode1_producers():
    producers = {}
    for r in mode1_rules():
        producers.setdefault(r["conclusion"][0], []).append(r)
    return producers


def fact_inputs(rule):
    keys = []
    for fk, _, exp in rule.get("conditions", []):
        keys.append(fk)
        if isinstance(exp, dict) and "ref" in exp:
            keys.append(exp["ref"])
    return keys


def facts_behind(key, producers, seen):
    if key in MODE_1_DEFAULTS:
        return [key]
    if key in seen:
        return []
    seen.add(key)
    out = []
    for rule in producers.get(key, []):
        for k in fact_inputs(rule):
            out.extend(facts_behind(k, producers, seen))
    return out


def ordered_with_parents(keys):
    wanted = set(keys)
    result = []

    def add(k):
        if k in result or k not in MODE_1_DEFAULTS:
            return
        parent = DEPENDS.get(k)
        if parent and parent[0] in MODE_1_DEFAULTS:
            add(parent[0])
        result.append(k)

    for k in fact_order(1):
        if k in wanted:
            add(k)
    return result


def section_facts(name, closure):
    own = []
    for sec, keys in MODE_1_SECTIONS:
        if sec == name:
            own = list(keys)
    if not closure:
        return ordered_with_parents(own)

    own_set = set(own)
    producers = mode1_producers()
    collected = list(own)
    for rule in mode1_rules():
        inputs = fact_inputs(rule)
        if any(k in own_set for k in inputs):
            for k in inputs:
                collected.extend(facts_behind(k, producers, set()))
    return ordered_with_parents(collected)


def reuse_text(keys):
    ss = st.session_state
    return "; ".join(f"{label_of(k)} ({show_value(ss.answers[k])})" for k in keys)


def m1_queue_section(name, closure):
    ss = st.session_state
    facts = section_facts(name, closure)
    queued = {k for k, _ in ss.queue}
    reused = [k for k in facts if k in ss.answers]
    new = [k for k in facts if k not in ss.answers and k not in queued]
    if not new:
        if reused:
            ss.messages.append(("assistant",
                                f"Checking {name}. Everything it needs was already answered above: "
                                f"{reuse_text(reused)}."))
        return
    if reused:
        ss.section_notes[name] = reused
    ss.queue.extend((k, name) for k in new)


def m1_advance():
    ss = st.session_state
    ss.current_q = None
    while ss.queue:
        key, section = ss.queue[0]
        if key in ss.answers:
            ss.queue.pop(0)
            continue
        ok, _ = dependency_status(1, key, ss.answers)
        if not ok:
            ss.queue.pop(0)
            continue
        if section != ss.current_section:
            ss.current_section = section
            ss.messages.append(("assistant", f"Checking {section}."))
            reused = ss.section_notes.pop(section, [])
            if reused:
                ss.messages.append(("assistant", f"Already answered above, used again: {reuse_text(reused)}."))
        ss.current_q = key
        return

    if ss.stage == "core":
        ss.stage = "choose"
        ss.current_section = None
        ss.messages.append(("assistant",
                            "The requester's account checks are done. Now choose the areas to check. "
                            "For each one I ask its questions and the questions its rules depend on."))
    else:
        finish_chat()


def start_mode1():
    ss = st.session_state
    ss.stage = "core"
    ss.branches = []
    core = section_facts(CORE_SECTION_NAME, False)
    ss.scope_facts = set(core)
    ss.queue = [(k, CORE_SECTION_NAME) for k in core]
    m1_advance()


def stop_for_eligibility(key):
    ss = st.session_state
    reason = HARD_STOP_FACTS[key]
    ss.stop_reason = reason
    ss.queue = []
    ss.current_q = None
    ss.current_section = None
    ss.stage = "advisory"
    ss.messages.append(("assistant",
                        f"{reason}, so this request cannot proceed, and I will not ask further "
                        "requester-side questions. Secret-side areas do not depend on who is asking, "
                        "so you can still check them as advisory findings."))


def m1_begin(names):
    ss = st.session_state
    ss.messages.append(("user", "Areas chosen: " + (", ".join(names) if names else "none")))
    ss.branches = [CORE_SECTION_NAME] + [n for n in names if n != CORE_SECTION_NAME]
    ss.stage = "asking"
    closure = ss.stop_reason is None
    for name in names:
        ss.scope_facts |= set(section_facts(name, closure))
        m1_queue_section(name, closure)
    m1_advance()


def choose_extras():
    ss = st.session_state
    chosen = [n for n in (ss.get("extra_choice") or []) if n in EXTRA_SECTIONS_MODE1]
    m1_begin(chosen)


def stop_at_core():
    m1_begin([])


def choose_advisory():
    ss = st.session_state
    chosen = [n for n in (ss.get("advisory_choice") or []) if n in SECRET_SIDE_SECTIONS]
    m1_begin(chosen)


def stop_advisory():
    m1_begin([])


def add_areas(names):
    ss = st.session_state
    ss.messages.append(("user", "Also check: " + ", ".join(names)))
    ss.branches = list(ss.branches or []) + [n for n in names if n not in (ss.branches or [])]
    for name in names:
        ss.scope_facts |= set(section_facts(name, True))
        m1_queue_section(name, True)
    ss.result = None
    ss.stage = "asking"
    m1_advance()


def init_state():
    ss = st.session_state
    ss.setdefault("page", "home")
    ss.setdefault("mode", None)
    ss.setdefault("stage", "asking")
    ss.setdefault("branches", None)
    ss.setdefault("skipped_areas", [])
    ss.setdefault("answers", {})
    ss.setdefault("messages", [])
    ss.setdefault("result", None)
    ss.setdefault("result_facts", {})
    ss.setdefault("skipped", [])
    ss.setdefault("scenario", None)
    ss.setdefault("queue", [])
    ss.setdefault("current_q", None)
    ss.setdefault("current_section", None)
    ss.setdefault("section_notes", {})
    ss.setdefault("scope_facts", None)
    ss.setdefault("stop_reason", None)
    ss.setdefault("conflicts", [])
    ss.setdefault("resume_stage", None)
    for mode in (1, 2):
        for k, v in defaults_for(mode).items():
            ss.setdefault(f"f{mode}_{k}", v)


def go_page(page):
    st.session_state.page = page


def reset_chat(mode, start=True):
    ss = st.session_state
    ss.mode = mode
    ss.stage = "symptoms" if mode == 2 else "asking"
    ss.branches = None
    ss.skipped_areas = []
    ss.answers = {}
    ss.messages = []
    ss.result = None
    ss.result_facts = {}
    ss.skipped = []
    ss.scenario = None
    ss.queue = []
    ss.current_q = None
    ss.current_section = None
    ss.section_notes = {}
    ss.scope_facts = None
    ss.stop_reason = None
    ss.conflicts = []
    ss.resume_stage = None
    if start and mode == 1:
        start_mode1()


def open_mode(mode):
    ss = st.session_state
    if ss.mode != mode:
        reset_chat(mode)
    ss.page = f"mode{mode}"


def restart_chat():
    reset_chat(st.session_state.mode)


def rules_for_evaluation(mode, allowed, answers):
    """In-scope rules, plus any rule that reads a Not sure answer, directly or through
    another rule. The engine then reports those rules as not considered instead of
    dropping them silently."""
    base = in_scope_rules(mode, allowed)
    unknown = {k for k, v in answers.items() if v == UNKNOWN}
    if not unknown:
        return base

    pool = [r for r in ALL_RULES if r["mode"] == mode and r["logic"] not in SYNTHESIS_LOGICS]
    picked = {r["id"]: r for r in pool if set(fact_inputs(r)) & unknown}

    changed = True
    while changed:
        changed = False
        produced = {r["conclusion"][0] for r in picked.values()}
        for r in pool:
            if r["id"] not in picked and set(fact_inputs(r)) & produced:
                picked[r["id"]] = r
                changed = True

    seen = {r["id"] for r in base}
    return base + [r for r in picked.values() if r["id"] not in seen]


def finish_chat():
    ss = st.session_state
    facts = build_facts(ss.answers)
    allowed = allowed_for(ss.mode)
    ss.result = evaluate(rules_for_evaluation(ss.mode, allowed, ss.answers), facts, ss.mode)
    ss.result_facts = facts
    ss.skipped = skipped_report(ss.mode, ss.answers, allowed, ss.skipped_areas)
    ss.stage = "result"


def confirm_symptoms():
    ss = st.session_state
    chosen = list(ss.get("symptoms") or []) or list(BRANCHES_MODE2)
    ss.branches = chosen
    ss.skipped_areas = []
    everything = len(chosen) == len(BRANCHES_MODE2)
    ss.messages.append(("user", "Checking: " + ("all areas" if everything else ", ".join(chosen))))
    ss.stage = "asking"
    announce_next_area(None)


def answer(key, value):
    ss = st.session_state
    ss.messages.append(("assistant", f"{label_of(key)}?"))
    ss.messages.append(("user", show_value(value)))
    ss.answers[key] = value
    for child in find_stale_answers(ss.answers, DEPENDS):
        ss.answers.pop(child, None)
        ss.messages.append(("assistant",
                            f"{label_of(child)} no longer applies, so its answer was removed."))
    conflicts = find_conflicts(ss.answers, ss.mode)
    if conflicts:
        ss.conflicts = conflicts
        ss.resume_stage = ss.stage
        ss.stage = "conflict"
        return
    continue_after_answer(key)


def continue_after_answer(key):
    ss = st.session_state
    if ss.mode == 1:
        if ss.answers.get(key) is False and key in HARD_STOP_FACTS:
            stop_for_eligibility(key)
            return
        m1_advance()
        return
    previous = section_of(2, key)
    if next_question(2, ss.answers, ss.branches) is None:
        finish_chat()
    else:
        announce_next_area(previous)


def resume_after_conflict():
    ss = st.session_state
    for child in find_stale_answers(ss.answers, DEPENDS):
        ss.answers.pop(child, None)
    ss.conflicts = []
    ss.stage = ss.resume_stage or "asking"
    ss.resume_stage = None
    if ss.mode == 1:
        if ss.answers.get("account_active") is False or ss.answers.get("account_not_locked") is False:
            for k in HARD_STOP_FACTS:
                if ss.answers.get(k) is False:
                    stop_for_eligibility(k)
                    return
        m1_advance()
    elif next_question(2, ss.answers, ss.branches) is None:
        finish_chat()
    else:
        announce_next_area(None)


def resolve_change(key):
    ss = st.session_state
    ss.answers.pop(key, None)
    ss.messages.append(("user", f"Changing: {label_of(key)}"))
    if ss.mode == 1:
        section = section_of(1, key) or CORE_SECTION_NAME
        ss.queue = [(k, s) for k, s in ss.queue if k != key]
        ss.queue.insert(0, (key, section))
    resume_after_conflict()


def resolve_unknown(key):
    ss = st.session_state
    ss.answers[key] = UNKNOWN
    ss.messages.append(("user", f"{label_of(key)}: Not sure (not considered)"))
    resume_after_conflict()


def answer_typed(key):
    ss = st.session_state
    raw = ss.get(f"in_{ss.mode}_{key}")
    if fact_kind(ss.mode, key) == "number":
        value = int(raw)
    else:
        value = str(raw or "").strip()
        if not value:
            return
    answer(key, value)


def skip_current_area(key):
    ss = st.session_state
    area = branch_of(key)
    if area is not None and ss.branches and area in ss.branches:
        ss.branches = [b for b in ss.branches if b != area]
        ss.skipped_areas = ss.skipped_areas + [area]
        ss.messages.append(("user", f"Skip the rest of {area}."))
    if next_question(2, ss.answers, ss.branches) is None:
        finish_chat()
    else:
        announce_next_area(area)


def skip_rest():
    st.session_state.messages.append(("user", "Finish now. Unanswered questions will not be considered."))
    finish_chat()


def edit_answer(key):
    ss = st.session_state
    ss.answers.pop(key, None)
    ss.messages.append(("user", f"Changing: {label_of(key)}"))
    ss.scenario = None
    if ss.mode == 1:
        if ss.stop_reason and key in HARD_STOP_FACTS:
            ss.stop_reason = None
            ss.stage = "core"
            ss.current_section = None
            ss.result = None
            ss.queue = [(k, CORE_SECTION_NAME) for k in section_facts(CORE_SECTION_NAME, False)
                        if k not in ss.answers]
            m1_advance()
            return
        ss.queue.insert(0, (key, section_of(1, key) or CORE_SECTION_NAME))
        if ss.stage != "core":
            ss.stage = "asking"
            ss.result = None
        m1_advance()
        return
    if next_question(2, ss.answers, ss.branches) is None:
        finish_chat()
    else:
        ss.result = None
        ss.stage = "asking"


def load_scenario(mode, index):
    ss = st.session_state
    presets = MODE_1_PRESETS if mode == 1 else MODE_2_PRESETS
    preset = presets[index]
    reset_chat(mode, start=False)
    ss.answers = apply_preset(mode, index)
    ss.scenario = preset["name"]
    ss.messages = [("user", f"Scenario loaded: {preset['name']}")]
    ss.result_facts = dict(ss.answers)
    ss.result = evaluate(in_scope_rules(mode, None), ss.answers, mode)
    ss.skipped = []
    ss.stage = "result"


def evaluate_form(mode):
    ss = st.session_state
    facts = {k: ss[f"f{mode}_{k}"] for k in defaults_for(mode)}
    ss[f"form_result_{mode}"] = evaluate(ALL_RULES, facts, mode)


CUSTOM_CSS = """
<style>
    .banner { padding: 1.1rem 1.4rem; border-radius: 6px; margin: 0.75rem 0 1rem 0;
              background: #F8FAFC; border-left: 8px solid; }
    .banner h2 { color: #0F172A !important; margin: 0 !important; font-size: 1.5rem !important; font-weight: 700 !important; }
    .banner p { color: #334155 !important; margin: 0.25rem 0 0 0 !important; font-size: 0.95rem !important; }
    .decision-approve { border-left-color: #10B981; }
    .decision-deny { border-left-color: #EF4444; }
    .decision-escalate { border-left-color: #F59E0B; }
    .decision-incomplete { border-left-color: #94A3B8; }
    .severity-critical { border-left-color: #DC2626; }
    .severity-high { border-left-color: #EA580C; }
    .severity-medium { border-left-color: #D97706; }
    .severity-low { border-left-color: #2563EB; }
    .severity-info { border-left-color: #94A3B8; }
    .welcome { text-align: center; padding: 0.5rem 1rem 1.5rem 1rem; }
    .welcome h1 { font-size: 3rem !important; font-weight: 700 !important; color: #64748B !important; margin-bottom: 0.25rem !important; }
    .welcome h2 { font-size: 1.25rem !important; font-weight: 400 !important; color: #64748B !important; margin-bottom: 2rem !important; }
    .page-title { color: #0F172A; font-size: 1.75rem !important; font-weight: 600 !important; margin-bottom: 0.25rem !important; }
    .page-subtitle { color: #64748B; font-size: 1rem !important; margin-bottom: 1.25rem !important; }
    .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #94A3B8;
              text-align: center; color: #64748B; font-size: 0.85rem; }
    .footer a { color: #2563EB; }
</style>
"""


ABOUT_CSS = """
<style>
    .spec { width: 100%; border-collapse: collapse; font-size: 0.92rem; margin: 0.5rem 0 1.25rem 0; }
    .spec td { padding: 0.45rem 0.6rem; border-bottom: 1px solid #334155; color: #E2E8F0; vertical-align: top; }
    .spec td:first-child { width: 32%; color: #CBD5E1; font-family: ui-monospace, Consolas, monospace; font-size: 0.85rem; }
    .about-tag { display: inline-block; font-family: ui-monospace, Consolas, monospace; font-size: 0.75rem;
                 color: #7DD3FC; border: 1px solid #334155; border-radius: 3px; padding: 0.1rem 0.45rem; margin-right: 0.35rem; }
</style>
"""


def render_access_verdict(result, names, possible, nc_count, stop):
    decision = result["decision"] or "unknown"
    css = {"approve": "decision-approve", "deny": "decision-deny",
           "escalate": "decision-escalate", "incomplete": "decision-incomplete"}.get(decision, "decision-deny")
    word = {"approve": "APPROVED", "deny": "DENIED", "escalate": "ESCALATED",
            "incomplete": "INCOMPLETE"}.get(decision, decision.upper())
    st.markdown(
        f'<div class="banner {css}"><h2>{word}</h2>'
        f'<p>{len(possible)} possible finding(s) · {nc_count} not considered</p></div>',
        unsafe_allow_html=True,
    )

    r14 = next((e for e in result["trace"] if e["rule_id"] == "R14"), {})
    triggers = [t for t in r14.get("fired_triggers", []) if not t.startswith("(")]
    if stop:
        lean = (f"{stop}, so the request cannot proceed, whatever the other checks show. "
                "Any secret-side findings below are advisory only.")
    elif decision == "deny":
        if triggers:
            reasons = "; ".join(names.get(t, t) for t in triggers)
            lean = f"The evidence leans DENY. Confirmed reasons: {reasons}."
        else:
            lean = "The evidence leans DENY because the requester is not eligible for evaluation."
    elif decision == "escalate":
        lean = "The evidence leans ESCALATE. A sensitivity or role check needs a manager's review first."
    elif decision == "incomplete":
        lean = (f"No confirmed reason to deny was found, but {nc_count} check(s) were not considered "
                "because their questions were skipped or marked Not sure. This is not a clearance. "
                "Answer those questions before relying on the decision.")
    else:
        lean = "The evidence leans APPROVE, and every check in this scope was considered. No confirmed reason to deny was found."
    st.markdown(f"**Why:** {lean}")
    if possible:
        st.markdown(
            "**Caution:** the evidence may also point to the possible findings listed below. "
            "Verify them before relying on the decision."
        )


def render_incident_verdict(result, trace, confirmed, possible, nc_count, mode):
    ss = st.session_state
    dec = result["decision"] or {}
    severity = dec.get("severity", "info")
    primary_id = dec.get("primary_diagnosis_rule_id")
    primary = next((e for e in trace if e["rule_id"] == primary_id), None)
    skipped = list(ss.skipped_areas or [])
    scope_note = f"{', '.join(skipped)} skipped. " if skipped else ""
    next_text = dec.get("next_step", "")

    if primary is None:
        severity = "info"
        if nc_count:
            headline = "NO CONFIRMED CAUSE"
            lean = (f"No rule fired on the answers given. {nc_count} check(s) were not considered "
                    "because their questions were skipped or marked Not sure, so those checks are not ruled out.")
            where = ", ".join(skipped) if skipped else "the unanswered areas"
            next_text = (f"Answer the skipped or Not sure questions, or check {where} directly "
                         "before relying on this result.")
        else:
            headline = "NO INCIDENT PATTERN MATCHED"
            lean = "No rule fired on the facts supplied. Areas that were skipped or not selected were not checked."
    elif primary["status"] == STATUS_CONFIRMED:
        headline = f"{severity.upper()} · {primary['rule_name']}"
        lean = f"Most likely cause (confirmed): {primary['rule_name']}."
    else:
        headline = f"POSSIBLE · {primary['rule_name']}"
        lean = (f"The evidence leans toward {primary['rule_name']}, but it is not confirmed. "
                "Possible findings are capped at medium severity.")

    st.markdown(
        f'<div class="banner severity-{severity}"><h2>{headline}</h2>'
        f'<p>{scope_note}{len(confirmed)} confirmed · {len(possible)} possible · {nc_count} not considered</p></div>',
        unsafe_allow_html=True,
    )
    st.markdown(f"**Why:** {lean}")
    if primary is not None and nc_count:
        st.caption(f"{nc_count} check(s) were not considered, so other causes in those areas are not ruled out.")
    st.markdown(f"**Recommended next step:** {next_text}")


def render_findings(confirmed, possible):
    if confirmed:
        st.markdown("**Confirmed findings**")
        for e in confirmed:
            st.markdown(f"- **{e['rule_name']}** ({e['rule_id']}): {e['recommendation']}")
    if possible:
        st.markdown("**Possible findings (wording says *may*, not confirmed)**")
        for e in possible:
            st.markdown(f"- **{e['rule_name']}** ({e['rule_id']}): {e['recommendation']}")


def render_not_considered(mode, items):
    if not items:
        return
    st.markdown(f"**Not considered ({len(items)})**")
    st.caption("These checks were not evaluated because the answers they need were skipped or marked Not sure. "
               "They are not ruled out, and no default was assumed.")
    for item in items:
        needs = ", ".join(missing_label(mode, m) for m in item["missing"]) or "unanswered inputs"
        st.markdown(f"- **{item['rule_name']}** ({item['rule_id']}): waiting on {needs}")


def render_overlap_view(fired, depths):
    st.markdown("#### How the findings combine")
    if not fired:
        st.caption("No findings to combine.")
        return
    levels = {1: [], 2: [], 3: []}
    for e in fired:
        levels[min(depths.get(e["rule_id"], 1), 3)].append(e)
    titles = {
        1: "Single findings",
        2: "Pair overlaps (two findings combined)",
        3: "Triple and deeper overlaps (combinations of combined findings)",
    }
    for lvl in (1, 2, 3):
        if levels[lvl]:
            st.markdown(f"**{titles[lvl]}**")
            for e in levels[lvl]:
                st.markdown(f"- {e['rule_name']} *({e['status']})*")
    st.caption("Each level is built from the levels below it. A combined finding appears only when its inputs are present.")


def render_reasoning(trace, mode, key_prefix):
    with st.expander("Reasoning trace"):
        fired = [e for e in trace if e["fired"]]
        not_fired = [e for e in trace if not e["fired"]]
        if fired:
            st.markdown("**Fired**")
            for e in fired:
                lines = [f"**✓ {e['rule_name']}** ({e['rule_id']}), {e['status']}"]
                for c in e.get("conditions", []):
                    if c.get("matched"):
                        lines.append(f"- {describe_condition(c, mode)}")
                for t in e.get("fired_triggers", []):
                    lines.append(f"- deny trigger: {t}")
                st.markdown("\n".join(lines))
        st.markdown("**Not indicated or not considered**")
        for e in not_fired:
            st.markdown(f"- {e['rule_name']} ({e['rule_id']}): {why_not(e, mode)}")


def render_skipped(skipped):
    if not skipped:
        return
    with st.expander(f"Not asked or not checked ({len(skipped)})"):
        for label, reason in skipped:
            st.markdown(f"- {label}: {reason}")


def render_result(mode, result, skipped, key_prefix, stop=None):
    if result.get("error"):
        st.error(f"Engine error: {result['error']}")
        return

    trace = result["trace"]
    depths = rule_depths(mode)
    fired = [e for e in trace if e["fired"] and e["rule_id"] in depths]
    confirmed = [e for e in fired if e["status"] == STATUS_CONFIRMED]
    possible = [e for e in fired if e["status"] == STATUS_POSSIBLE]
    not_considered = result.get("not_considered", [])
    nc_count = len(not_considered)

    if mode == 1:
        render_access_verdict(result, conclusion_names(1), possible, nc_count, stop)
    else:
        render_incident_verdict(result, trace, confirmed, possible, nc_count, mode)

    render_findings(confirmed, possible)
    render_not_considered(mode, not_considered)
    render_overlap_view(fired, depths)
    render_reasoning(trace, mode, key_prefix)
    render_skipped(skipped)

    export = {
        "timestamp": datetime.now().isoformat(),
        "mode": mode,
        "decision": result["decision"],
        "stop_reason": stop,
        "possible_findings": result.get("possible_findings", []),
        "not_considered": not_considered,
        "trace": [
            {
                "rule_id": e["rule_id"],
                "rule_name": e["rule_name"],
                "status": e["status"],
                "conditions": e.get("conditions", []),
                "recommendation": e["recommendation"],
                "severity": e.get("severity"),
            }
            for e in trace
        ],
        "not_asked_or_not_checked": skipped,
    }
    st.download_button(
        "Download result (JSON)",
        data=json.dumps(export, indent=2, default=str),
        file_name=f"vsecretserveradvisor_mode{mode}_{datetime.now():%Y%m%d_%H%M%S}.json",
        mime="application/json",
        key=f"{key_prefix}_download",
    )


def render_question_inputs(mode, key):
    ss = st.session_state
    kind = fact_kind(mode, key)
    default = defaults_for(mode)[key]

    if kind in ("bool", "choice"):
        if kind == "bool":
            items = [("Yes", True), ("No", False)]
        else:
            items = [(v, v) for v in ENUM_OPTIONS[key]]
        items.append(("Not sure", UNKNOWN))
        for idx, (text, value) in enumerate(items):
            if idx % 4 == 0:
                cols = st.columns(4)
            cols[idx % 4].button(
                text,
                key=f"q_{mode}_{key}_{idx}",
                on_click=answer,
                args=(key, value),
            )
        return

    wkey = f"in_{mode}_{key}"
    if kind == "number":
        ss.setdefault(wkey, int(default))
        st.number_input(label_of(key), key=wkey, step=1, label_visibility="collapsed")
    else:
        ss.setdefault(wkey, str(default))
        st.text_input(label_of(key), key=wkey, label_visibility="collapsed")
    c1, c2 = st.columns(2)
    c1.button("Submit", key=f"sub_{mode}_{key}", on_click=answer_typed, args=(key,))
    c2.button("Not sure", key=f"unk_{mode}_{key}", on_click=answer, args=(key, UNKNOWN))


def render_scenarios(mode):
    presets = MODE_1_PRESETS if mode == 1 else MODE_2_PRESETS
    with st.expander("Common Scenarios"):
        for idx, preset in enumerate(presets):
            if idx % 4 == 0:
                cols = st.columns(4)
            cols[idx % 4].button(
                preset["name"],
                key=f"scn_{mode}_{idx}",
                help=preset["description"],
                on_click=load_scenario,
                args=(mode, idx),
            )


def unchecked_sections(mode):
    ss = st.session_state
    if mode != 1 or ss.branches is None or ss.scenario or ss.stop_reason:
        return []
    return [n for n in EXTRA_SECTIONS_MODE1 if n not in ss.branches]


def render_chat(mode):
    ss = st.session_state

    with st.chat_message("assistant"):
        st.write(INTRO[mode])
    for role, text in ss.messages:
        with st.chat_message(role):
            st.write(text)

    if ss.stage == "symptoms":
        with st.chat_message("assistant"):
            st.write("Which areas seem to be misbehaving? Pick any that apply, or leave it empty to check everything.")
        st.multiselect("Areas", list(BRANCHES_MODE2), key="symptoms", label_visibility="collapsed")
        st.button("Continue", key="continue_symptoms", type="primary", on_click=confirm_symptoms)

    elif ss.stage == "conflict":
        with st.chat_message("assistant"):
            st.write("Two of your answers cannot both be true, so I have not run the check. "
                     "Change one of them, or mark it Not sure.")
        for i, conflict in enumerate(ss.conflicts):
            st.warning(conflict["message"])
            cols = st.columns(2 * len(conflict["facts"]))
            for j, fk in enumerate(conflict["facts"]):
                cols[2 * j].button(f"Change: {label_of(fk)} ({show_value(ss.answers.get(fk))})",
                                   key=f"cf_chg_{i}_{j}", on_click=resolve_change, args=(fk,))
                cols[2 * j + 1].button("Not sure", key=f"cf_unk_{i}_{j}",
                                       on_click=resolve_unknown, args=(fk,))

    elif ss.stage == "choose":
        with st.chat_message("assistant"):
            st.write("Which areas do you want to check? Choose one or more. Choose none to stop here "
                     "with a preliminary result.")
        st.multiselect("Areas to check", EXTRA_SECTIONS_MODE1, key="extra_choice",
                       label_visibility="collapsed")
        c1, c2 = st.columns(2)
        c1.button("Check selected areas", key="extra_go", type="primary", on_click=choose_extras)
        c2.button("Stop here (preliminary result)", key="extra_stop", on_click=stop_at_core)

    elif ss.stage == "advisory":
        with st.chat_message("assistant"):
            st.write("Which secret-side areas do you want to check? These are advisory only and do not "
                     "change the eligibility result. Choose none to finish.")
        st.multiselect("Advisory areas", SECRET_SIDE_SECTIONS, key="advisory_choice",
                       label_visibility="collapsed")
        c1, c2 = st.columns(2)
        c1.button("Check selected (advisory)", key="advisory_go", type="primary", on_click=choose_advisory)
        c2.button("Finish with eligibility result", key="advisory_stop", on_click=stop_advisory)

    elif ss.stage in ("core", "asking"):
        key = ss.current_q if mode == 1 else next_question(mode, ss.answers, ss.branches)
        if key is None:
            finish_chat()
            st.rerun()
        with st.chat_message("assistant"):
            st.write(f"**{label_of(key)}?**")
        render_question_inputs(mode, key)
        if mode == 2:
            st.button(f"Skip the rest of {branch_of(key)}", key=f"skip_area_{mode}",
                      on_click=skip_current_area, args=(key,))
        st.button("Finish now (unanswered questions will not be considered)", key=f"skip_{mode}",
                  on_click=skip_rest)

    if ss.stage == "result":
        remaining = unchecked_sections(mode)
        with st.chat_message("assistant"):
            st.write("Here is my assessment from your answers. Change any answer in the panel on the right.")
        if remaining:
            st.warning(
                "Preliminary result. These areas were not part of this check: "
                + ", ".join(remaining)
                + ". Rules in those areas were not run, so a clean result here does not cover them."
            )
        stop = ss.stop_reason if mode == 1 else None
        render_result(mode, ss.result, ss.skipped, key_prefix=f"chat{mode}", stop=stop)
        if remaining:
            st.markdown("**Add more areas and re-check**")
            for i, name in enumerate(remaining):
                if i % 3 == 0:
                    cols = st.columns(3)
                cols[i % 3].button(f"Check {name}", key=f"add_{i}", on_click=add_areas, args=([name],))
            if len(remaining) > 1:
                st.button("Check all remaining areas", key="add_all", on_click=add_areas, args=(remaining,))


def render_belief_panel(mode):
    ss = st.session_state
    st.markdown("#### What the advisor currently knows")
    if mode == 1 and not ss.scenario:
        if ss.stage == "conflict":
            st.caption("Waiting for you to resolve conflicting answers. No verdict until then.")
        elif ss.stop_reason:
            st.caption(f"Stopped: {ss.stop_reason}.")
        elif ss.stage == "core":
            st.caption("Checking the requester's account first.")
        elif ss.stage == "choose":
            st.caption("Waiting for you to choose the areas to check.")
        elif ss.stage == "advisory":
            st.caption("Eligibility failed. Secret-side areas are available as advisory only.")
        elif ss.stage == "asking" and ss.current_section:
            st.caption(f"Checking: {ss.current_section}")
        elif ss.stage == "result" and ss.branches is not None:
            st.caption(f"Areas in this check: {len(ss.branches)} of {len(ALL_SECTIONS_MODE1)}")
    if mode == 2:
        if ss.stage == "symptoms":
            st.caption("Waiting for you to choose the areas to check.")
        elif ss.stage == "conflict":
            st.caption("Waiting for you to resolve conflicting answers. No verdict until then.")
        else:
            active = ", ".join(ss.branches) if ss.branches else "none left"
            st.caption(f"Checking: {active}")
            if ss.skipped_areas:
                st.caption(f"Skipped by you: {', '.join(ss.skipped_areas)}")

    if ss.scenario:
        st.info(f"Scenario: {ss.scenario}. Every value comes from the scenario. Use the form tab to change values by hand.")
    elif not ss.answers:
        st.caption("No answers yet.")
    else:
        with st.expander(f"Answers so far ({len(ss.answers)})", expanded=True):
            for key, value in list(ss.answers.items()):
                c1, c2 = st.columns([3, 1])
                c1.markdown(f"**{label_of(key)}**: {show_value(value)}")
                c2.button("Change", key=f"chg_{mode}_{key}", on_click=edit_answer, args=(key,))

    st.button("Start over", key=f"restart_{mode}", on_click=restart_chat)


def render_form_widget(mode, key):
    wkey = f"f{mode}_{key}"
    label = label_of(key)
    kind = fact_kind(mode, key)
    if kind == "bool":
        st.toggle(label, key=wkey)
    elif kind == "number":
        st.number_input(label, key=wkey, step=1)
    elif kind == "choice":
        options = list(ENUM_OPTIONS[key])
        current = st.session_state[wkey]
        if current not in options:
            options = [current] + options
        st.selectbox(label, options, key=wkey)
    else:
        st.text_input(label, key=wkey)


def render_form_tab(mode):
    ss = st.session_state
    st.caption("Fallback to the chat. Same rules, same engine. The form starts with a healthy baseline, "
               "so change the fields that describe your case, then press Evaluate.")
    for name, keys in sections_for(mode):
        with st.expander(name):
            cols = st.columns(2)
            for i, k in enumerate(keys):
                with cols[i % 2]:
                    render_form_widget(mode, k)
    st.button("Evaluate form", type="primary", key=f"form_eval_{mode}",
              on_click=evaluate_form, args=(mode,))
    result = ss.get(f"form_result_{mode}")
    if result is not None:
        render_result(mode, result, [], key_prefix=f"form{mode}")


def render_footer():
    st.markdown(
        f'<div class="footer">© {datetime.now().year} VSecretServerAdvisor · '
        f'<a href="{GITHUB_URL}" target="_blank">Github</a> · '
        "Decision support only. Check the result against your own policy before acting.</div>",
        unsafe_allow_html=True,
    )


def render_home():
    c1, c2, c3 = st.columns([3, 1, 3])
    with c2:
        if LOGO.exists():
            st.image(str(LOGO), width=200)

    st.markdown(
        '<div class="welcome"><h1>VSecretServerAdvisor</h1>'
        '<h2>Secret Server Expert System</h2></div>',
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        st.button("Access Evaluator", use_container_width=True, key="go_mode1",
                  on_click=open_mode, args=(1,))
        st.button("Incident Diagnostician", use_container_width=True, key="go_mode2",
                  on_click=open_mode, args=(2,))
        st.button("About", use_container_width=True, key="go_about",
                  on_click=go_page, args=("about",))
    render_footer()


def render_mode_page(mode):
    st.button("← Back", key=f"back_{mode}", on_click=go_page, args=("home",))
    st.markdown(f'<h1 class="page-title">{MODE_NAMES[mode]}</h1>', unsafe_allow_html=True)
    subtitle = {
        1: "Evaluates whether a privileged access request should be approved, denied, or escalated.",
        2: "Diagnoses what is wrong when Secret Server or its dependencies (IIS, SQL, AD, network) misbehave.",
    }[mode]
    st.markdown(f'<p class="page-subtitle">{subtitle}</p>', unsafe_allow_html=True)

    chat_tab, form_tab = st.tabs(["Advisor", "Form"])
    with chat_tab:
        render_scenarios(mode)
        left, right = st.columns([3, 2])
        with left:
            render_chat(mode)
        with right:
            render_belief_panel(mode)
    with form_tab:
        render_form_tab(mode)

    render_footer()


def rule_stats():
    stats = {}
    for mode in (1, 2):
        rules = [r for r in ALL_RULES if r["mode"] == mode]
        tests = sum(len(r.get("conditions", [])) + len(r.get("deny_triggers", [])) for r in rules)
        stats[mode] = {
            "rules": len(rules),
            "tests": tests,
            "layers": max(rule_depths(mode).values()),
        }
    stats["total_rules"] = stats[1]["rules"] + stats[2]["rules"]
    stats["total_tests"] = stats[1]["tests"] + stats[2]["tests"]
    return stats


def render_about():
    st.markdown(ABOUT_CSS, unsafe_allow_html=True)
    st.button("← Back", key="back_from_about", on_click=go_page, args=("home",))

    s = rule_stats()

    st.markdown('<h1 class="page-title">About VSecretServerAdvisor</h1>', unsafe_allow_html=True)

    st.markdown("### What it is")
    st.markdown(
        "VSecretServerAdvisor is a rule-based expert system for Delinea Secret Server, a "
        "privileged access management (PAM) platform. It gives decision support: it helps an "
        "administrator reason through a situation, and it shows every rule that led to its answer. "
        "It does not make changes to Secret Server."
    )

    st.markdown("### The problem it solves")
    st.markdown(
        "Privileged accounts are the keys to an organisation's systems, so access to them has to be "
        "controlled. Each request raises questions: is the account in good standing, is MFA in place, "
        "does the secret need approval, is the access in line with policy? Checking these by hand is "
        "slow and easy to get wrong under pressure.\n\n"
        "When Secret Server or the services it depends on misbehave, administrators also need to find "
        "the cause quickly. A web tier failure, a database problem, a directory sync error, and a "
        "heartbeat failure can look alike from the outside. The advisor works through the likely causes "
        "in the order the evidence supports."
    )

    st.markdown("### Why it was built")
    st.markdown(
        "The aim was to turn the reasoning of an experienced administrator into explicit rules that a reviewer can read, test, and challenge."
    )

    st.markdown("### Who it is for")
    st.markdown(
        "- Secret Server administrators who want a structured check before approving access, or a "
        "checklist when something breaks.\n"
        "- Security reviewers who need to see why a request was approved, denied, or escalated.\n"
        "- Anyone who wants to understand how a privileged access decision or an incident diagnosis "
        "was reached."
    )

    st.markdown("### How to use it")
    st.markdown(
        "**Access Evaluator.** Answer the requester's account checks first. Then choose the areas to "
        "check. Read the decision, then the list of checks that were not run.\n\n"
        "**Incident Diagnostician.** Choose the areas that seem to be misbehaving. Answer the questions "
        "for each area, and skip any area you cannot check. Read the likely cause and the next step.\n\n"
        "**Common scenarios.**"
    )

    st.markdown("### How to read a result")
    st.markdown(
        "**Confirmed** means a rule fired on facts you supplied.\n\n"
        "**Possible** means a rule fired on partial evidence. Its wording uses *may*, and it cannot "
        "raise severity above medium or force a denial.\n\n"
        "**Not considered** means a rule could not be evaluated because an answer was skipped or marked "
        "Not sure. It is not treated as passing.\n\n"
        "A result is only as good as the answers behind it. Check the Not considered list before "
        "relying on any verdict."
    )

    st.markdown("### What it does not do")
    st.markdown(
        "- It does not connect to your Secret Server or any live system. It checks only the answers you enter.\n"
        "- It does not verify that an answer is true. It catches some contradictions between answers, "
        "but only the ones listed in its validator.\n"
        "- It does not replace your organisation's policy or a person's judgement.\n"
        "- It does not learn from past cases, and it keeps no record between sessions.\n"
        "- It covers only the rules it contains. A clean result does not mean no other problem exists."
    )

    st.markdown("### Sources")
    st.markdown(
        "Rules are drawn from the Delinea Secret Server documentation on QuantumLock, IIS, SQL Server, "
        "Active Directory credential caching, and heartbeat and RPC rotation."
    )

    st.markdown("### Version and scope")
    st.markdown(
        f"""
<table class="spec">
<tr><td>Access Evaluator</td><td>{s[1]['rules']} rules, {s[1]['tests']} condition tests, {s[1]['layers']} reasoning layers</td></tr>
<tr><td>Incident Diagnostician</td><td>{s[2]['rules']} rules, {s[2]['tests']} condition tests, {s[2]['layers']} reasoning layers</td></tr>
<tr><td>Total</td><td>{s['total_rules']} rules, {s['total_tests']} condition tests</td></tr>
<tr><td>Inference</td><td>Forward chaining to a fixed point, then a single synthesis pass</td></tr>
<tr><td>Input integrity</td><td>Conflicting answers stop the flow before any verdict. Stale answers are removed</td></tr>
<tr><td>Implementation</td><td>Python, Streamlit. Five modules: knowledge base, inference engine, utilities, input validator, interface</td></tr>
</table>
""",
        unsafe_allow_html=True,
    )

    st.markdown("### Source code")
    st.markdown(
        "Repository: [GitHub Profile](https://github.com/Vertive-Foundation/VSecretServerAdvisor)"
    )

    render_footer()


def main():
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    init_state()

    page = st.session_state.page
    if page == "home":
        render_home()
    elif page == "mode1":
        render_mode_page(1)
    elif page == "mode2":
        render_mode_page(2)
    elif page == "about":
        render_about()
    else:
        st.session_state.page = "home"
        st.rerun()


if __name__ == "__main__":
    main()