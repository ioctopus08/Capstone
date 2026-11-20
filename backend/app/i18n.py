"""Minimal AZ/EN label set for report rendering."""

LABELS = {
    "en": {
        "title": "Static Malware Triage Report",
        "file": "File",
        "verdict": "Verdict",
        "score": "Risk Score",
        "reasons": "Why this score",
        "sections": "PE Sections",
        "imports": "Imported DLLs",
        "anomalies": "Anomalies",
        "yara": "YARA Matches",
        "attack": "MITRE ATT&CK Techniques",
        "iocs": "Indicators of Compromise",
        "urls": "URLs",
        "domains": "Domains",
        "ips": "Public IPs",
        "private_ips": "Private IPs (internal)",
        "hashes": "Hashes found in sample",
        "az_note": "This sample references .az infrastructure - review for look-alike domains and report to CERT.AZ if confirmed malicious.",
        "generated": "Generated",
        "limitations": "Limitations",
        "limitations_text": "Static analysis only - packers/obfuscation can hide behavior. Windows PE files only. No sandbox/behavioral data in this build.",
    },
    "az": {
        "title": "Statik Zərərli Proqram Triyaj Hesabatı",
        "file": "Fayl",
        "verdict": "Nəticə",
        "score": "Risk Balı",
        "reasons": "Balın səbəbləri",
        "sections": "PE Bölmələri",
        "imports": "İdxal Edilən DLL-lər",
        "anomalies": "Anomaliyalar",
        "yara": "YARA Uyğunlaşmaları",
        "attack": "MITRE ATT&CK Taktikaları",
        "iocs": "Təhlükə Göstəriciləri (IOC)",
        "urls": "URL-lər",
        "domains": "Domenlər",
        "ips": "Açıq IP-lər",
        "private_ips": "Daxili IP-lər",
        "hashes": "Nümunədə tapılan heş-lər",
        "az_note": "Bu nümunə .az infrastrukturuna istinad edir - saxta (look-alike) domenləri yoxlayın və zərərli təsdiqlənərsə CERT.AZ-a bildirin.",
        "generated": "Yaradılma tarixi",
        "limitations": "Məhdudiyyətlər",
        "limitations_text": "Yalnız statik təhlil - paketləyicilər/obfuskasiya davranışı gizlədə bilər. Yalnız Windows PE faylları. Bu versiyada sandbox/davranış analizi yoxdur.",
    },
}


def t(lang: str, key: str) -> str:
    lang = lang if lang in LABELS else "en"
    return LABELS[lang].get(key, key)
