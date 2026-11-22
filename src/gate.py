"""
gate.py

The deterministic safety gate (Gate 2 in the "sandwich" design).

The agent's output is treated as UNTRUSTED input. Before any response action we:
  1. parse the JSON              (bad JSON -> escalate)
  2. validate against the schema (missing/extra/wrong fields -> escalate)
  3. apply safety rules the agent does not control, per domain:
       - confidence floor (all domains)
       - endpoint : never auto-contain critical hosts; workstation only
       - identity : never auto-disable privileged/admin accounts
       - cloud    : never auto-disable keys on protected production resources
Anything that fails any check falls toward a human ("escalate"), never toward an
action. "contain: true" is mapped to the correct action for the domain.

Zero dependencies: tiny hand-rolled schema check. In production you would use
the `jsonschema` library with schema/containment_output.schema.json.
"""

import json

CONFIDENCE_FLOOR = 0.80

# Endpoint guardrails.
CRITICAL_HOSTS = {"DC01", "DC02", "PAYMENTS-DB", "EXCHANGE01"}
# Identity guardrails: disabling these would cause an outage or lockout.
PRIVILEGED_USERS = {"breakglass@corp.com", "svc-azuread@corp.com", "admin@corp.com"}
# Cloud guardrails: protected resources need a human before key disable.
PROTECTED_CLOUD = {"root", "arn:aws:iam::acct:user/prod-deploy", "terraform-ci"}

# What "contain: true" means in each domain.
ACTION_BY_DOMAIN = {
    "endpoint": "contain_host",
    "identity": "disable_user",
    "cloud": "disable_access_key",
}


def validate_schema(obj) -> tuple[bool, str]:
    """Hand-rolled mirror of schema/containment_output.schema.json."""
    if not isinstance(obj, dict):
        return False, "output is not a JSON object"
    required = {"explanation": str, "confidence": (int, float), "contain": bool}
    for field, expected in required.items():
        if field not in obj:
            return False, f"missing required field: {field}"
        if field == "confidence" and isinstance(obj[field], bool):
            return False, "confidence must be a number, not a boolean"
        if not isinstance(obj[field], expected):
            return False, f"wrong type for {field}"
    extra = set(obj) - set(required)
    if extra:
        return False, f"unexpected field(s): {', '.join(sorted(extra))}"
    return True, "ok"


def _domain_guardrail(detection: dict) -> tuple[bool, str]:
    """Per-domain safety rule. Returns (safe_to_auto_act, reason_if_not)."""
    domain = detection.get("domain", "endpoint")

    if domain == "endpoint":
        host = detection.get("host", "")
        if host in CRITICAL_HOSTS:
            return False, f"{host} is a critical host; human must approve"
        if detection.get("host_type") != "Workstation":
            return False, f"host type {detection.get('host_type')} is not a Workstation"

    elif domain == "identity":
        user = detection.get("user", "")
        if user in PRIVILEGED_USERS:
            return False, f"{user} is a privileged account; human must approve"

    elif domain == "cloud":
        resource = detection.get("resource", "")
        if resource in PROTECTED_CLOUD or detection.get("env") == "production":
            return False, f"{resource} is protected/production; human must approve"

    return True, "ok"


def decide(detection: dict, agent_output: str) -> dict:
    """Decide the final action from the detection and the agent's JSON output.
    Returns {"action": <domain action>|"escalate", "reason": str, "agent": dict|None}."""
    try:
        rec = json.loads(agent_output)
    except json.JSONDecodeError:
        return {"action": "escalate", "reason": "agent output was not valid JSON", "agent": None}

    ok, reason = validate_schema(rec)
    if not ok:
        return {"action": "escalate", "reason": f"schema invalid: {reason}", "agent": None}

    if not rec["contain"]:
        return {"action": "escalate", "reason": "agent did not recommend action", "agent": rec}

    if rec["confidence"] < CONFIDENCE_FLOOR:
        return {"action": "escalate",
                "reason": f"confidence {rec['confidence']} below floor {CONFIDENCE_FLOOR}",
                "agent": rec}

    safe, why = _domain_guardrail(detection)
    if not safe:
        return {"action": "escalate", "reason": why, "agent": rec}

    domain = detection.get("domain", "endpoint")
    return {"action": ACTION_BY_DOMAIN[domain], "reason": "all safety checks passed", "agent": rec}
