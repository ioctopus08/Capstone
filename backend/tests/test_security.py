"""Security regression tests for the API layer. Run with:
    venv\\Scripts\\python.exe -m pytest tests -v
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

from app import main, security
from app.ioc_extract import MAX_IOCS_PER_TYPE, extract_iocs
from app.main import app, build_report

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    security.rate_limiter._hits.clear()
    yield
    security.rate_limiter._hits.clear()


def test_security_headers_present():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert "server" not in r.headers


def test_health_does_not_leak_internal_errors():
    assert set(client.get("/api/health").json()["yara"]) == {"available"}


def test_docs_disabled_by_default():
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_untrusted_host_rejected():
    # DNS-rebinding protection: an attacker domain resolving to 127.0.0.1.
    r = client.get("/api/health", headers={"Host": "evil.example.com"})
    assert r.status_code == 400


def test_cors_rejects_unknown_origin():
    r = client.get("/api/health", headers={"Origin": "https://evil.example.com"})
    assert "access-control-allow-origin" not in r.headers


def test_cors_allows_frontend_origin():
    r = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


@pytest.mark.parametrize("name", ["../app/main.py", "..\\..\\x.exe", "%2e%2e/x.exe", "main.py", ".hidden.exe"])
def test_sample_path_traversal_blocked(name):
    r = client.post("/api/analyze-sample", params={"name": name})
    assert r.status_code in (404, 422)


def test_invalid_report_language_rejected():
    r = client.post("/api/report/html-sample", params={"name": "synthetic_suspicious.exe", "lang": "<script>"})
    assert r.status_code == 422


def test_oversized_upload_rejected(monkeypatch):
    small = security.BodySizeLimitMiddleware(app, max_bytes=1024)
    limited = TestClient(small)
    r = limited.post("/api/analyze", files={"file": ("big.exe", b"A" * 5000)})
    assert r.status_code == 413


def test_empty_upload_rejected():
    r = client.post("/api/analyze", files={"file": ("empty.exe", b"")})
    assert r.status_code == 400


def test_filename_is_sanitized():
    r = client.post("/api/analyze", files={"file": ("..\\..\\evil\x00<b>.exe", b"MZ not really a pe")})
    assert r.status_code == 200
    name = r.json()["file"]["name"]
    assert "\\" not in name and "/" not in name and "\x00" not in name


def test_html_report_escapes_and_has_csp():
    r = client.post(
        "/api/report/html",
        params={"lang": "en"},
        files={"file": ("<script>alert(1)</script>.exe", b"MZ hello http://evil-test.com/<img>")},
    )
    assert r.status_code == 200
    assert "<script>alert(1)" not in r.text
    assert "Content-Security-Policy" in r.text
    assert "style-src 'unsafe-inline'" in r.headers["content-security-policy"]


def test_rate_limit_enforced(monkeypatch):
    monkeypatch.setattr(security.rate_limiter, "limit", 3)
    codes = [client.post("/api/analyze", files={"file": ("a.bin", b"data")}).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3] == 429


def test_api_key_enforced_when_configured(monkeypatch):
    monkeypatch.setattr(security.settings, "api_key", "s3cret")
    assert client.post("/api/analyze", files={"file": ("a.bin", b"data")}).status_code == 401
    assert client.get("/api/samples").status_code == 401
    ok = client.post("/api/analyze", files={"file": ("a.bin", b"data")}, headers={"X-API-Key": "s3cret"})
    assert ok.status_code == 200


def test_redos_strings_are_fast():
    # Before the fix, a single 32KB dotted string took ~40s to process.
    hostile = ["a." * 50_000, "1." * 50_000, "http://" + "a." * 50_000]
    start = time.time()
    extract_iocs(hostile)
    assert time.time() - start < 3


def test_ioc_output_is_capped():
    flood = [f"http://host{i}.example.com/x" for i in range(MAX_IOCS_PER_TYPE * 3)]
    iocs = extract_iocs(flood)
    assert len(iocs["urls"]) == MAX_IOCS_PER_TYPE


def test_benign_domain_in_path_does_not_hide_malicious_url():
    # Evasion fix: "microsoft.com" in the *path* must not allowlist the URL.
    iocs = extract_iocs(["http://evil-c2.test/microsoft.com/payload"])
    assert any("evil-c2" in u for u in iocs["urls"])


def test_malformed_pe_does_not_crash():
    data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + os.urandom(2000)
    report = build_report("broken.exe", data)
    assert report["score"]["value"] >= 0


def test_internal_errors_are_not_leaked(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("secret internal path C:\\secret")

    monkeypatch.setattr(main, "build_report", boom)
    safe_client = TestClient(app, raise_server_exceptions=False)
    r = safe_client.post("/api/analyze", files={"file": ("a.bin", b"data")})
    assert r.status_code == 500
    assert "secret" not in r.text
