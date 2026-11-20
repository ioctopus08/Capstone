"""PE header metadata, import tagging and interesting-string extraction."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

from app.interesting_strings import MAX_PER_CATEGORY, extract_interesting_strings
from app.main import app, build_report

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def _synthetic_report():
    with open(os.path.join(SAMPLES_DIR, "synthetic_suspicious.exe"), "rb") as f:
        return build_report("synthetic_suspicious.exe", f.read())


def test_pe_headers_extracted():
    h = _synthetic_report()["pe"]["headers"]
    assert h["machine"] == "x86 (32-bit)"
    assert h["file_type"] == "EXE"
    assert h["compile_time"] is None and h["timestamp_raw"] == 0
    assert h["entry_point"].startswith("0x")
    assert h["aslr"] is False and h["dep"] is False


def test_clean_binary_headers_look_normal():
    path = os.path.join(SAMPLES_DIR, "clean_sample.exe")
    if not os.path.exists(path):
        return  # optional local fixture
    with open(path, "rb") as f:
        report = build_report("clean_sample.exe", f.read())
    h = report["pe"]["headers"]
    assert h["compile_time"] is not None
    assert h["aslr"] and h["dep"]
    # Clean file must stay clean even though its own settings key is extracted.
    assert report["score"]["verdict"] == "Clean"


def test_suspicious_imports_tagged():
    tagged = {s["api"]: s["category"] for s in _synthetic_report()["pe"]["suspicious_imports"]}
    assert tagged == {
        "VirtualAllocEx": "injection",
        "WriteProcessMemory": "injection",
        "CreateRemoteThread": "injection",
    }


def test_interesting_strings_and_host_iocs():
    report = _synthetic_report()
    found = report["strings"]["interesting"]
    assert "Software\\Microsoft\\Windows\\CurrentVersion\\Run" in found["autorun_registry"]
    assert "HKEY_CURRENT_USER\\Software\\DemoDropper\\Config" in found["registry"]  # UTF-16 string
    assert found["mutexes"] == ["Global\\IOCtopusDemoMutex_7f3a"]
    assert any("svchost32.exe" in p for p in found["paths"])
    assert any("schtasks" in c for c in found["commands"])
    assert any(u.startswith("Mozilla/5.0") for u in found["user_agents"])
    assert report["iocs"]["mutexes"] == found["mutexes"]
    assert report["iocs"]["registry_keys"] == found["registry"]
    assert report["strings"]["total"] == report["strings"]["ascii"] + report["strings"]["wide"]


def test_interesting_strings_are_bounded_and_fast():
    hostile = ["HKLM\\" + "A" * 100_000, "C:\\" + "\\a" * 50_000] + [f"Global\\mutex_{i:05d}" for i in range(1000)]
    start = time.time()
    out = extract_interesting_strings(hostile)
    assert time.time() - start < 2
    assert len(out["mutexes"]) == MAX_PER_CATEGORY
    assert all(len(v) <= 300 for values in out.values() for v in values)


def test_html_report_shows_new_sections():
    client = TestClient(app)
    r = client.post("/api/report/html-sample", params={"name": "synthetic_suspicious.exe", "lang": "en"})
    assert r.status_code == 200
    for text in ("PE Header", "x86 (32-bit)", "CreateRemoteThread", "Interesting strings",
                 "Global\\IOCtopusDemoMutex_7f3a", "Autorun / persistence location", "SHA256"):
        assert text in r.text, text
    az = client.post("/api/report/html-sample", params={"name": "synthetic_suspicious.exe", "lang": "az"})
    assert "PE Başlığı" in az.text and "Maraqlı sətirlər" in az.text
