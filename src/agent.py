"""
agent.py

A stand-in for the Charlotte AI AgentWorks "Containment Analysis Agent".

In the real workshop this is an LLM grounded on the CISA playbook, calling
sub-agents (triage, command-line analysis, intel, query) and returning JSON.
Here we simulate that judgment step deterministically so the project runs with
no API keys. The important part for the design is the CONTRACT: whatever the
agent decides, across endpoint, identity, or cloud, it returns exactly
{explanation, confidence, contain}. The gate maps that boolean to the right
domain-specific action.

To prove the deterministic gate works, this module can also emit deliberately
BAD output via the `mode` argument, mimicking a misbehaving or manipulated LLM.
"""

import json

from detections import score


def analyze_detection(detection: dict, mode: str = "normal") -> str:
    """Return a JSON string, exactly as the AgentWorks agent would."""
    analysis = score(detection)
    risk = analysis["risk_score"]
    hits = analysis["hits"]

    contain = risk >= 70
    confidence = round(min(0.99, risk / 100 + 0.05), 2)
    if hits:
        explanation = "Evidence of malicious activity: " + "; ".join(hits) + "."
    else:
        explanation = "No high-risk techniques observed."

    result = {"explanation": explanation, "confidence": confidence, "contain": contain}

    if mode == "overconfident":
        result.update(contain=True, confidence=0.95,
                      explanation="Looks bad, acting. (weak evidence)")
    elif mode == "malformed":
        del result["contain"]
    elif mode == "rogue":
        result["delete_everything"] = True  # not in the approved schema

    return json.dumps(result)
