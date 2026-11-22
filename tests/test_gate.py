"""
Unit tests for the deterministic gate, across all three domains.

Run from the project root:
  python3 -m unittest discover -s tests -v

Each test proves the gate catches one class of bad agent output, or allows a
clean action for the right domain.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from gate import decide, CONFIDENCE_FLOOR  # noqa: E402

WORKSTATION = {"domain": "endpoint", "host": "ECL-WKS-0421", "host_type": "Workstation"}
IDENTITY = {"domain": "identity", "user": "swilson@corp.com"}
CLOUD = {"domain": "cloud", "resource": "arn:aws:iam::acct:user/deploy", "env": "staging"}


def agent(contain=True, confidence=0.95, explanation="malicious", **extra):
    payload = {"contain": contain, "confidence": confidence, "explanation": explanation}
    payload.update(extra)
    return json.dumps(payload)


class TestGateValidation(unittest.TestCase):

    def test_malformed_json_escalates(self):
        self.assertEqual(decide(WORKSTATION, "{nope")["action"], "escalate")

    def test_missing_field_escalates(self):
        bad = json.dumps({"confidence": 0.9, "explanation": "x"})
        self.assertEqual(decide(WORKSTATION, bad)["action"], "escalate")

    def test_extra_field_escalates(self):
        self.assertEqual(decide(WORKSTATION, agent(delete_everything=True))["action"], "escalate")

    def test_low_confidence_escalates(self):
        self.assertEqual(decide(WORKSTATION, agent(confidence=CONFIDENCE_FLOOR - 0.01))["action"], "escalate")

    def test_contain_false_escalates(self):
        self.assertEqual(decide(WORKSTATION, agent(contain=False))["action"], "escalate")

    def test_confidence_as_bool_rejected(self):
        bad = json.dumps({"contain": True, "confidence": True, "explanation": "x"})
        self.assertEqual(decide(WORKSTATION, bad)["action"], "escalate")


class TestEndpointDomain(unittest.TestCase):

    def test_clean_contain_host(self):
        self.assertEqual(decide(WORKSTATION, agent())["action"], "contain_host")

    def test_critical_host_escalates(self):
        dc = {"domain": "endpoint", "host": "DC01", "host_type": "Server"}
        self.assertEqual(decide(dc, agent())["action"], "escalate")

    def test_non_workstation_escalates(self):
        srv = {"domain": "endpoint", "host": "APP-SRV-10", "host_type": "Server"}
        self.assertEqual(decide(srv, agent())["action"], "escalate")


class TestIdentityDomain(unittest.TestCase):

    def test_clean_disable_user(self):
        self.assertEqual(decide(IDENTITY, agent())["action"], "disable_user")

    def test_privileged_user_escalates(self):
        priv = {"domain": "identity", "user": "breakglass@corp.com"}
        self.assertEqual(decide(priv, agent())["action"], "escalate")


class TestCloudDomain(unittest.TestCase):

    def test_clean_disable_key(self):
        self.assertEqual(decide(CLOUD, agent())["action"], "disable_access_key")

    def test_production_escalates(self):
        prod = {"domain": "cloud", "resource": "root", "env": "production"}
        self.assertEqual(decide(prod, agent())["action"], "escalate")


if __name__ == "__main__":
    unittest.main()
