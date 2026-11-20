"""Smoke tests: a clean system-style binary must not be flagged malicious,
and the synthetic suspicious fixture must be. Run with:
    venv\\Scripts\\python.exe -m pytest tests -v
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.main import build_report

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def test_clean_binary_is_not_flagged_malicious():
    path = os.path.join(SAMPLES_DIR, "clean_sample.exe")
    if not os.path.exists(path):
        return  # optional fixture, only present after copying a local system binary
    data = open(path, "rb").read()
    report = build_report("clean_sample.exe", data)
    assert report["score"]["verdict"] in ("Clean", "Suspicious"), report["score"]
    assert report["score"]["value"] < 50, report["score"]


def test_synthetic_suspicious_sample_scores_high():
    path = os.path.join(SAMPLES_DIR, "synthetic_suspicious.exe")
    data = open(path, "rb").read()
    report = build_report("synthetic_suspicious.exe", data)
    assert report["score"]["value"] >= 50, report["score"]
    technique_ids = {a["technique"] for a in report["attack"]}
    assert "T1055" in technique_ids
    assert any(y["rule"] == "Contains_EICAR_Test_String" for y in report["yara"])
    assert any("evil-example-c2" in u for u in report["iocs"]["urls"])


def test_large_legit_installer_is_not_flagged_az_related():
    # Regression test: a Node.js MSI hosted on Azure CDN (*.azureedge.net) was
    # scored "Suspicious" because ".az" was matched as a raw substring anywhere
    # in a URL, and because raw URL *count* alone could cross the Suspicious
    # threshold. Neither should happen for an ordinary installer full of real
    # license/docs/CDN links.
    fake_installer = b" ".join(
        [
            b"https://nodejs.org/dist/v26.13.1/node.exe",
            b"https://nodejsorg.azureedge.net/release/v26.13.1/node.exe",
            b"https://github.com/nodejs/node/blob/main/LICENSE",
        ]
        + [f"https://example-doc-link-{i}.com/page".encode() for i in range(85)]
    )
    report = build_report("fake_node.msi", fake_installer)
    assert report["iocs"]["az_related"] == [], report["iocs"]["az_related"]
    assert report["score"]["verdict"] == "Clean", report["score"]


def test_non_pe_file_does_not_crash():
    data = b"just a plain text file, not a PE, with no special content here."
    report = build_report("notes.txt", data)
    assert report["pe"]["is_pe"] is False
    assert report["score"]["value"] >= 0
