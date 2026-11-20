"""Explained 0-100 risk score: every point added carries a plain-text reason."""

YARA_SEVERITY_WEIGHTS = {"high": 30, "medium": 20, "low": 10, "info": 0}
ATTACK_CONFIDENCE_WEIGHTS = {"high": 30, "medium": 15, "low": 6}
ANOMALY_WEIGHTS = {
    "high_entropy_section": 20,
    "packer_signature": 15,
    "no_imports": 10,
    "future_timestamp": 8,
    "zero_timestamp": 5,
    "tls_callback": 10,
    "size_mismatch": 8,
    "not_a_pe": 0,
    "engine_unavailable": 0,
}
# Deliberately small and capped well below the "Suspicious" threshold (20): any
# large legitimate installer (an MSI, a browser, an office suite) legitimately
# contains dozens of real URLs (license, docs, CDN, telemetry opt-out), so raw
# URL/domain *count* must never be able to flip the verdict on its own - it's
# shown for analyst context, not treated as a standalone risk signal.
IOC_URL_WEIGHT_PER_ITEM = 1
IOC_URL_WEIGHT_CAP = 6
AZ_INFRA_FLAG_WEIGHT = 15


def compute_score(pe_result: dict, yara_matches: list, attack_findings: list, iocs: dict) -> dict:
    reasons = []
    total = 0

    for match in yara_matches:
        weight = YARA_SEVERITY_WEIGHTS.get(match.get("severity", "medium"), 15)
        if weight <= 0:
            continue
        total += weight
        reasons.append(f"+{weight} YARA: {match['rule']} ({match['severity']})")

    for finding in attack_findings:
        weight = ATTACK_CONFIDENCE_WEIGHTS.get(finding.get("confidence", "low"), 6)
        total += weight
        reasons.append(f"+{weight} ATT&CK {finding['technique']} ({finding['name']})")

    seen_entropy_bonus = False
    for anomaly in pe_result.get("anomalies", []):
        weight = ANOMALY_WEIGHTS.get(anomaly["type"], 0)
        if weight <= 0:
            continue
        # Only count the strongest entropy flag once to avoid double-counting per section.
        if anomaly["type"] == "high_entropy_section":
            if seen_entropy_bonus:
                continue
            seen_entropy_bonus = True
        total += weight
        reasons.append(f"+{weight} {anomaly['detail']}")

    url_count = len(iocs.get("urls", [])) + len(iocs.get("domains", []))
    if url_count:
        bonus = min(url_count * IOC_URL_WEIGHT_PER_ITEM, IOC_URL_WEIGHT_CAP)
        total += bonus
        reasons.append(f"+{bonus} {url_count} external URL/domain indicator(s) found")

    if iocs.get("az_related"):
        total += AZ_INFRA_FLAG_WEIGHT
        reasons.append(f"+{AZ_INFRA_FLAG_WEIGHT} references .az infrastructure ({len(iocs['az_related'])} indicator(s)) - review for look-alike domains")

    total = min(total, 100)

    if total >= 80:
        verdict = "Malicious"
    elif total >= 50:
        verdict = "Likely Malicious"
    elif total >= 20:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    return {"value": total, "verdict": verdict, "reasons": reasons}
