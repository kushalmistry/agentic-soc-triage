"""
pipeline.py

Ties the whole "agentic SOC" workflow together, mirroring Scenario 3, and now
routes endpoint, identity, and cloud detections through the same pattern:

  detection
    -> Gate 1: trigger + severity filter   (deterministic)
    -> Agent: judgment call, returns JSON   (non-deterministic in real life)
    -> Gate 2: validate + domain safety     (deterministic)
    -> Action: domain-specific OR escalate
    -> Case: audit record on every path

Run it:  python3 src/pipeline.py
"""

import json
import os

from agent import analyze_detection
from gate import decide

SEVERITY_RANK = {"Informational": 10, "Low": 30, "Medium": 50, "High": 70, "Critical": 90}
SEVERITY_FLOOR = SEVERITY_RANK["High"]  # Gate 1


def passes_severity_filter(detection: dict) -> bool:
    return SEVERITY_RANK.get(detection.get("severity", "Low"), 0) >= SEVERITY_FLOOR


def create_case(detection: dict, result: dict) -> dict:
    agent = result.get("agent") or {}
    return {
        "title": "Detection Escalation - Agentic SOC Review",
        "severity": "High",
        "domain": detection.get("domain", "endpoint"),
        "entity": detection.get("host") or detection.get("user") or detection.get("resource"),
        "detection": detection.get("name"),
        "action_taken": result["action"],
        "reason": result["reason"],
        "agent_contain": agent.get("contain"),
        "agent_confidence": agent.get("confidence"),
        "agent_explanation": agent.get("explanation"),
    }


def run(detection: dict, agent_mode: str = "normal") -> dict:
    if not passes_severity_filter(detection):
        return {"title": "Skipped (below severity floor)",
                "domain": detection.get("domain", "endpoint"),
                "entity": detection.get("host") or detection.get("user") or detection.get("resource"),
                "action_taken": "skip", "reason": "severity below High"}
    agent_output = analyze_detection(detection, mode=agent_mode)
    result = decide(detection, agent_output)
    return create_case(detection, result)


def _load_samples() -> list:
    path = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_detections.json")
    with open(path) as f:
        return json.load(f)


if __name__ == "__main__":
    for det in _load_samples():
        case = run(det)
        print(f"\n[{case['domain']:8}] {case['entity']}  ::  {det.get('name', '')}")
        print(f"  action : {case['action_taken']}")
        print(f"  reason : {case['reason']}")
        if case.get("agent_explanation"):
            print(f"  agent  : contain={case['agent_contain']} "
                  f"conf={case['agent_confidence']} :: {case['agent_explanation']}")
