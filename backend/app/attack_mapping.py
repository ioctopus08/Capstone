"""Map observed import API sets to MITRE ATT&CK techniques."""
from app.pe_analysis import INJECTION_APIS, PERSISTENCE_APIS, ANTI_DEBUG_APIS, NETWORK_APIS, KEYLOG_APIS

TECHNIQUE_RULES = [
    {
        # Legitimate software essentially never imports all three of these
        # together - this combination is a reliable, high-confidence signal.
        "technique": "T1055",
        "name": "Process Injection",
        "required": INJECTION_APIS,
        "min_hits": 3,
        "confidence": "high",
    },
    {
        # Any one of these APIs alone is routine in ordinary Windows software
        # (saving settings, anti-tamper in games, etc.) - kept as low-weight
        # context, not treated as strong malicious evidence by itself.
        "technique": "T1547",
        "name": "Boot or Logon Autostart Execution (Registry)",
        "required": PERSISTENCE_APIS,
        "min_hits": 2,
        "confidence": "low",
    },
    {
        "technique": "T1622",
        "name": "Debugger Evasion",
        "required": ANTI_DEBUG_APIS,
        "min_hits": 1,
        "confidence": "low",
    },
    {
        "technique": "T1071",
        "name": "Application Layer Protocol (C2/network)",
        "required": NETWORK_APIS,
        "min_hits": 1,
        "confidence": "low",
    },
    {
        "technique": "T1056",
        "name": "Input Capture (Keylogging)",
        "required": KEYLOG_APIS,
        "min_hits": 2,
        "confidence": "medium",
    },
]


def map_attack_techniques(all_apis: list) -> list:
    api_set = set(all_apis)
    findings = []
    for rule in TECHNIQUE_RULES:
        hits = api_set & rule["required"]
        if len(hits) >= rule["min_hits"]:
            findings.append({
                "technique": rule["technique"],
                "name": rule["name"],
                "confidence": rule["confidence"],
                "reason": f"Imports {', '.join(sorted(hits))} together",
            })
    return findings
