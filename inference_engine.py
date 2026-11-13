import operator as _op

MAX_PASSES = 20
MAX_DEPTH = 25
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
POSSIBLE_SEVERITY_CAP = "medium"
SYNTHESIS_LOGICS = ("DECISION_MATRIX", "PRIORITY_FIRST")
SYNTHESIS_OUTPUTS = ("decision", "next_step", "severity")

STATUS_CONFIRMED = "confirmed"
STATUS_POSSIBLE = "possible"
STATUS_NOT_INDICATED = "not_indicated"
STATUS_NOT_CONSIDERED = "not_considered"

FIRES = "fires"
NO = "no"
UNDECIDED = "undecided"

OPERATORS = {
    "==": _op.eq,
    "!=": _op.ne,
    "<": _op.lt,
    ">": _op.gt,
    "<=": _op.le,
    ">=": _op.ge,
    "in": lambda actual, expected: actual in expected,
    "not_in": lambda actual, expected: actual not in expected,
}


def _validate(rules):
    ids = [r["id"] for r in rules]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"Duplicate rule IDs: {duplicates}")
    for r in rules:
        if r.get("logic") in SYNTHESIS_LOGICS:
            computes = r.get("computes")
            if computes not in SYNTHESIS_OUTPUTS:
                raise ValueError(f"Synthesis rule {r['id']} must set 'computes' to one of {SYNTHESIS_OUTPUTS}.")
            if computes == "decision" and "deny_triggers" not in r:
                raise ValueError(f"Decision rule {r['id']} must list 'deny_triggers'.")


def _condition_keys(fact_key, expected):
    keys = [fact_key]
    if isinstance(expected, dict) and "ref" in expected:
        keys.append(expected["ref"])
    return keys


def _resolve(key, working, producers, depth=0):
    if key in working:
        return True, working[key]
    if depth > MAX_DEPTH:
        return False, None
    rules_for_key = producers.get(key)
    if not rules_for_key:
        return False, None
    states = [_rule_state(r, working, producers, depth + 1)[0] for r in rules_for_key]
    if all(s == NO for s in states):
        return True, False
    return False, None


def _root_missing(key, working, producers, depth=0):
    if key in working or depth > MAX_DEPTH:
        return set()
    rules_for_key = producers.get(key)
    if not rules_for_key:
        return {key}
    missing = set()
    for rule in rules_for_key:
        for fact_key, _, expected in rule.get("conditions", []):
            for k in _condition_keys(fact_key, expected):
                known, _ = _resolve(k, working, producers)
                if not known:
                    missing |= _root_missing(k, working, producers, depth + 1)
    return missing


def _check(condition, working, producers, depth=0):
    fact_key, op_name, expected = condition
    result = {
        "fact_key": fact_key,
        "operator": op_name,
        "expected_value": expected,
        "actual_value": None,
        "matched": False,
        "unknown": False,
        "missing": [],
    }

    known, actual = _resolve(fact_key, working, producers, depth)
    if not known:
        result["unknown"] = True
        result["missing"] = sorted(_root_missing(fact_key, working, producers))
        return result
    result["actual_value"] = actual

    if op_name in ("in", "not_in"):
        compare_to = expected
    elif isinstance(expected, dict) and "ref" in expected:
        known, compare_to = _resolve(expected["ref"], working, producers, depth)
        if not known:
            result["unknown"] = True
            result["missing"] = sorted(_root_missing(expected["ref"], working, producers))
            return result
    else:
        compare_to = expected

    try:
        result["matched"] = bool(OPERATORS[op_name](actual, compare_to))
    except (KeyError, TypeError, ValueError):
        result["matched"] = False
    return result


def _rule_state(rule, working, producers, depth=0):
    results = [_check(c, working, producers, depth) for c in rule.get("conditions", [])]
    if not results:
        return NO, results
    if rule.get("logic", "AND") == "OR":
        if any(r["matched"] for r in results):
            return FIRES, results
        if any(r["unknown"] for r in results):
            return UNDECIDED, results
        return NO, results
    if any(not r["matched"] and not r["unknown"] for r in results):
        return NO, results
    if any(r["unknown"] for r in results):
        return UNDECIDED, results
    return FIRES, results


def _trace_entry(rule, conditions, status, conclusion=None, pass_number=None, order=None):
    return {
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "mode": rule["mode"],
        "category": rule["category"],
        "logic": rule["logic"],
        "severity": rule.get("severity"),
        "fired": status in (STATUS_CONFIRMED, STATUS_POSSIBLE),
        "status": status,
        "conditions": conditions,
        "conclusion": conclusion,
        "recommendation": rule["recommendation"],
        "pass_number": pass_number,
        "order_in_pass": order,
    }


def _severity_rank(severity):
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0


def _highest(entries):
    best = None
    for e in entries:
        if best is None or _severity_rank(e.get("severity")) > _severity_rank(best.get("severity")):
            best = e
    return best


def _decide_mode_1(rule, working, hedged, status_of, not_considered_count):
    triggers = [t for t in rule.get("deny_triggers", [])
                if working.get(t) is True and t not in hedged]
    if triggers:
        return "deny", triggers
    if status_of.get("R1") == STATUS_NOT_INDICATED:
        return "deny", ["(requester_not_eligible)"]
    if working.get("elevated_review_required") is True:
        return "escalate", []
    if not_considered_count:
        return "incomplete", []
    return "approve", []


def _summarise_mode_2(confirmed, possible, not_considered_count):
    base = {"not_considered_count": not_considered_count}
    if confirmed:
        primary = _highest(confirmed)
        return {**base,
                "severity": primary.get("severity") or "info",
                "next_step": primary["recommendation"],
                "primary_diagnosis_rule_id": primary["rule_id"]}
    if possible:
        primary = _highest(possible)
        severity = primary.get("severity") or "info"
        if _severity_rank(severity) > _severity_rank(POSSIBLE_SEVERITY_CAP):
            severity = POSSIBLE_SEVERITY_CAP
        return {**base,
                "severity": severity,
                "next_step": "Possible issue, not confirmed: " + primary["recommendation"],
                "primary_diagnosis_rule_id": primary["rule_id"]}
    if not_considered_count:
        return {**base,
                "severity": "info",
                "next_step": (f"No confirmed cause on the answers given. {not_considered_count} check(s) "
                              "were not considered because their questions were skipped or marked Not sure, "
                              "so they are not ruled out."),
                "primary_diagnosis_rule_id": None}
    return {**base,
            "severity": "info",
            "next_step": "No rule fired on the facts supplied.",
            "primary_diagnosis_rule_id": None}


def _run(rules, facts, mode):
    _validate(rules)
    regular = [r for r in rules if r.get("logic") not in SYNTHESIS_LOGICS]
    synthesis = [r for r in rules if r.get("logic") in SYNTHESIS_LOGICS]

    producers = {}
    for r in regular:
        producers.setdefault(r["conclusion"][0], []).append(r)

    working = dict(facts)
    hedged = set()
    fired = {}
    passes = 0
    converged = False

    while passes < MAX_PASSES:
        passes += 1
        order = 0
        changed = False
        for rule in regular:
            if rule["id"] in fired:
                continue
            state, results = _rule_state(rule, working, producers)
            if state != FIRES:
                continue
            order += 1
            is_hedged = rule.get("hedged", False) or any(
                r["matched"] and r["fact_key"] in hedged for r in results
            )
            key, value = rule["conclusion"]
            working[key] = value
            if is_hedged:
                hedged.add(key)
            else:
                hedged.discard(key)
            fired[rule["id"]] = _trace_entry(
                rule, results,
                STATUS_POSSIBLE if is_hedged else STATUS_CONFIRMED,
                conclusion=rule["conclusion"], pass_number=passes, order=order,
            )
            changed = True
        if not changed:
            converged = True
            break

    status_of = {}
    rest = []
    for rule in regular:
        if rule["id"] in fired:
            status_of[rule["id"]] = fired[rule["id"]]["status"]
            continue
        state, results = _rule_state(rule, working, producers)
        status = STATUS_NOT_INDICATED if state == NO else STATUS_NOT_CONSIDERED
        status_of[rule["id"]] = status
        rest.append(_trace_entry(rule, results, status))

    fired_entries = list(fired.values())
    confirmed = [e for e in fired_entries if e["status"] == STATUS_CONFIRMED]
    possible = [e for e in fired_entries if e["status"] == STATUS_POSSIBLE]
    not_considered_entries = [e for e in rest if e["status"] == STATUS_NOT_CONSIDERED]
    nc_count = len(not_considered_entries)

    mode_2_summary = _summarise_mode_2(confirmed, possible, nc_count)
    synthesis_entries = []
    for rule in synthesis:
        computes = rule["computes"]
        if computes == "decision":
            value, triggers = _decide_mode_1(rule, working, hedged, status_of, nc_count)
            working["final_decision"] = value
            entry = _trace_entry(rule, [], STATUS_CONFIRMED, conclusion=("final_decision", value))
            entry["fired_triggers"] = triggers
        else:
            value = mode_2_summary[computes]
            working[computes] = value
            entry = _trace_entry(rule, [], STATUS_CONFIRMED, conclusion=(computes, value))
            entry["severity"] = mode_2_summary["severity"]
        synthesis_entries.append(entry)

    trace = (
        sorted(fired_entries, key=lambda e: (e["pass_number"], e["order_in_pass"]))
        + synthesis_entries
        + sorted(rest, key=lambda e: e["rule_id"])
    )

    not_considered = [
        {
            "rule_id": e["rule_id"],
            "rule_name": e["rule_name"],
            "missing": sorted({m for c in e["conditions"] for m in c.get("missing", [])}),
        }
        for e in sorted(not_considered_entries, key=lambda e: e["rule_id"])
    ]

    decision = working.get("final_decision", "unknown") if mode == 1 else mode_2_summary

    possible_findings = [
        {"rule_id": e["rule_id"], "rule_name": e["rule_name"], "recommendation": e["recommendation"]}
        for e in possible
    ]

    return {
        "final_facts": working,
        "trace": trace,
        "decision": decision,
        "passes_used": passes,
        "possible_findings": possible_findings,
        "not_considered": not_considered,
        "converged": converged,
        "error": None,
    }


def evaluate(rules, facts, mode):
    empty = {
        "final_facts": {},
        "trace": [],
        "decision": None,
        "passes_used": 0,
        "possible_findings": [],
        "not_considered": [],
        "converged": False,
        "error": None,
    }

    if mode not in (1, 2):
        return {**empty, "error": f"Invalid mode: {mode}. Must be 1 or 2."}
    if not isinstance(facts, dict):
        return {**empty, "error": "facts must be a dict."}

    mode_rules = [r for r in rules if r.get("mode") == mode]
    if not mode_rules:
        return {**empty, "error": f"No rules found for mode {mode}."}

    try:
        return _run(mode_rules, facts, mode)
    except Exception as e:
        return {**empty, "final_facts": dict(facts),
                "error": f"Engine error: {type(e).__name__}: {e}"}