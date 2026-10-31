MAX_PASSES = 10
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

def _evaluate_condition(condition, facts):
    if len(condition) != 3:
        return False, None
    fact_key, operator, expected_value = condition

    if fact_key not in facts:
        return False, None
    actual_value = facts[fact_key]

    try:
        if operator == "==":
            matched = (actual_value == expected_value)
        elif operator == "!=":
            matched = (actual_value != expected_value)
        elif operator == "<":
            matched = (actual_value < expected_value)
        elif operator == ">":
            matched = (actual_value > expected_value)
        elif operator == "<=":
            matched = (actual_value <= expected_value)
        elif operator == ">=":
            matched = (actual_value >= expected_value)
        elif operator == "in":
            matched = (actual_value in expected_value)
        elif operator == "not_in":
            matched = (actual_value not in expected_value)
        else:
            matched = False
    except (TypeError, ValueError):
        matched = False

    return matched, actual_value

def _match_rule(rule, facts):
    logic = rule.get("logic", "AND")
    conditions = rule.get("conditions", [])
    condition_results = []

    short_circuited = False

    for cond in conditions:
        matched, actual_value = _evaluate_condition(cond, facts)

        if len(cond) == 3:
            fact_key, operator, expected_value = cond
        else:
            fact_key, operator, expected_value = None, None, None

        condition_results.append({
            "fact_key": fact_key,
            "operator": operator,
            "expected_value": expected_value,
            "actual_value": actual_value,
            "matched": matched,
            "fact_missing": fact_key is not None and fact_key not in facts,
        })

        if logic == "AND" and not matched:
            short_circuited = True
            break
        elif logic == "OR" and matched:
            short_circuited = True
            break

    if logic == "AND":
        should_fire = (not short_circuited) and all(c["matched"] for c in condition_results)
    elif logic == "OR":
        # OR fires if at least one condition matched
        should_fire = any(c["matched"] for c in condition_results)
    else:
        should_fire = False

    return should_fire, condition_results


def _handle_decision_matrix(rule, facts):
    deny_triggers = [
        "least_privilege_violation", "mfa_required", "aal3_required",
        "quantumlock_rotation_conflict", "quantumlock_lockout_risk",
        "two_person_approval_required", "session_recording_required",
        "rotation_overdue", "sod_violation", "time_bound_access_not_configured",
        "break_glass_audit_violation", "ep_infinite_loop_detected",
        "network_exposure_violation",
    ]

    fired_deny_triggers = [t for t in deny_triggers if facts.get(t) is True]

    eligible = facts.get("eligible_for_evaluation") is True
    elevated = facts.get("elevated_review_required") is True

    if fired_deny_triggers:
        decision = "deny"
    elif not eligible:
        decision = "deny"
        fired_deny_triggers = ["(requester_not_eligible)"]
    elif elevated:
        decision = "escalate"
    else:
        decision = "approve"

    return True, decision, fired_deny_triggers


def _handle_priority_first(fired_mode_2_entries):
    if not fired_mode_2_entries:
        return {
            "severity": "info",
            "next_step": "No incidents detected. System is operating normally.",
            "primary_diagnosis_rule_id": None,
        }

    def severity_index(entry):
        sev = entry.get("severity") or "info"
        return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 0

    sorted_entries = sorted(fired_mode_2_entries, key=severity_index, reverse=True)
    primary = sorted_entries[0]

    return {
        "severity": primary.get("severity") or "info",
        "next_step": primary.get("recommendation", ""),
        "primary_diagnosis_rule_id": primary.get("rule_id"),
    }


def _forward_chain(rules, facts, mode):
    trace = []
    fired_rule_ids = set()
    pass_number = 0
    working_facts = dict(facts)
    composite_rules = [r for r in rules if r.get("logic") in ("DECISION_MATRIX", "PRIORITY_FIRST")]
    regular_rules = [r for r in rules if r.get("logic") not in ("DECISION_MATRIX", "PRIORITY_FIRST")]

    while pass_number < MAX_PASSES:
        pass_number += 1
        rules_fired_this_pass = 0

        for rule in regular_rules:
            if rule["id"] in fired_rule_ids:
                continue  # Already fired, skip

            should_fire, condition_results = _match_rule(rule, working_facts)

            if should_fire:
                # Fire the rule: add its conclusion to facts
                concl_key, concl_value = rule["conclusion"]
                working_facts[concl_key] = concl_value
                fired_rule_ids.add(rule["id"])
                rules_fired_this_pass += 1

                trace.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "mode": rule["mode"],
                    "category": rule["category"],
                    "logic": rule["logic"],
                    "severity": rule.get("severity"),
                    "fired": True,
                    "conditions": condition_results,
                    "conclusion": rule["conclusion"],
                    "recommendation": rule["recommendation"],
                    "pass_number": pass_number,
                    "order_in_pass": rules_fired_this_pass,
                })


        for rule in composite_rules:
            if rule["id"] in fired_rule_ids:
                continue

            if rule["logic"] == "DECISION_MATRIX":
                if mode != 1:
                    continue

                _, decision_value, fired_triggers = _handle_decision_matrix(rule, working_facts)
                working_facts["final_decision"] = decision_value
                fired_rule_ids.add(rule["id"])
                rules_fired_this_pass += 1

                trace.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "mode": rule["mode"],
                    "category": rule["category"],
                    "logic": rule["logic"],
                    "severity": rule.get("severity"),
                    "fired": True,
                    "conditions": [],  # R14's conditions are the deny_triggers, shown separately
                    "conclusion": ("final_decision", decision_value),
                    "recommendation": rule["recommendation"],
                    "pass_number": pass_number,
                    "order_in_pass": rules_fired_this_pass,
                    "fired_triggers": fired_triggers,
                })

            elif rule["logic"] == "PRIORITY_FIRST":
                if mode != 2:
                    continue

                fired_mode_2_entries = [
                    {
                        "rule_id": e["rule_id"],
                        "rule_name": e["rule_name"],
                        "severity": e["severity"],
                        "recommendation": e["recommendation"],
                    }
                    for e in trace
                    if e.get("fired") and e.get("mode") == 2 and
                       e.get("logic") not in ("DECISION_MATRIX", "PRIORITY_FIRST")
                ]

                result = _handle_priority_first(fired_mode_2_entries)

                if rule["id"] == "R25":
                    working_facts["next_step"] = result["next_step"]
                    conclusion_value = result["next_step"]
                elif rule["id"] == "R26":
                    working_facts["severity"] = result["severity"]
                    conclusion_value = result["severity"]
                else:
                    continue

                fired_rule_ids.add(rule["id"])
                rules_fired_this_pass += 1

                trace.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "mode": rule["mode"],
                    "category": rule["category"],
                    "logic": rule["logic"],
                    "severity": rule.get("severity"),
                    "fired": True,
                    "conditions": [],
                    "conclusion": (rule["conclusion"][0], conclusion_value),
                    "recommendation": rule["recommendation"],
                    "pass_number": pass_number,
                    "order_in_pass": rules_fired_this_pass,
                    "priority_result": result,
                })

        if rules_fired_this_pass == 0:
            break  

    for rule in regular_rules:
        if rule["id"] in fired_rule_ids:
            continue
        _, condition_results = _match_rule(rule, working_facts)
        trace.append({
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "mode": rule["mode"],
            "category": rule["category"],
            "logic": rule["logic"],
            "severity": rule.get("severity"),
            "fired": False,
            "conditions": condition_results,
            "conclusion": None,
            "recommendation": rule["recommendation"],
            "pass_number": None,
            "order_in_pass": None,
        })

    fired_entries = sorted(
        [e for e in trace if e.get("fired")],
        key=lambda e: (e.get("pass_number") or 0, e.get("order_in_pass") or 0)
    )
    not_fired_entries = sorted(
        [e for e in trace if not e.get("fired")],
        key=lambda e: e.get("rule_id") or ""
    )

    return working_facts, fired_entries + not_fired_entries, pass_number

def evaluate(rules, facts, mode):
    if mode not in (1, 2):
        return {
            "final_facts": dict(facts),
            "trace": [],
            "decision": None,
            "passes_used": 0,
            "error": f"Invalid mode: {mode}. Must be 1 or 2.",
        }

    if not isinstance(facts, dict):
        return {
            "final_facts": {},
            "trace": [],
            "decision": None,
            "passes_used": 0,
            "error": "facts must be a dict.",
        }

    filtered_rules = [r for r in rules if r.get("mode") == mode]
    if not filtered_rules:
        return {
            "final_facts": dict(facts),
            "trace": [],
            "decision": None,
            "passes_used": 0,
            "error": f"No rules found for mode {mode}.",
        }


    try:
        final_facts, trace, passes_used = _forward_chain(filtered_rules, facts, mode)
    except Exception as e:
        return {
            "final_facts": dict(facts),
            "trace": [],
            "decision": None,
            "passes_used": 0,
            "error": f"Engine error: {type(e).__name__}: {str(e)}",
        }

    decision = None
    if mode == 1:
        decision = final_facts.get("final_decision", "unknown")
    elif mode == 2:
        severity = final_facts.get("severity", "info")
        next_step = final_facts.get("next_step", "No incidents detected.")
        # Find the primary diagnosis rule — highest-severity fired Mode 2 rule
        # that is NOT a synthesis rule (DECISION_MATRIX / PRIORITY_FIRST)
        fired_mode_2 = [
            e for e in trace
            if e.get("fired") and e.get("mode") == 2 and
            e.get("logic") not in ("DECISION_MATRIX", "PRIORITY_FIRST")
        ]
        primary_rule_id = None
        if fired_mode_2:
            def sev_idx(e):
                s = e.get("severity") or "info"
                return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 0
            fired_mode_2.sort(key=sev_idx, reverse=True)
            primary_rule_id = fired_mode_2[0].get("rule_id")

        decision = {
            "severity": severity,
            "next_step": next_step,
            "primary_diagnosis_rule_id": primary_rule_id,
        }

    return {
        "final_facts": final_facts,
        "trace": trace,
        "decision": decision,
        "passes_used": passes_used,
        "error": None,
    }
