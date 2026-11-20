# IOCtopus - Offline Static Malware Triage

A fully offline static-analysis triage tool for Windows PE files: PE/import parsing, YARA
(including an Azerbaijan-specific pack), IOC extraction with false-positive filtering, an
explained 0-100 risk score, MITRE ATT&CK mapping, and bilingual (AZ/EN) HTML/JSON/STIX
reports. Built for a 24-hour hackathon; designed to grow into the full capstone project
(sandbox execution + analyst dashboard).

## Why

Banks, government bodies and telecoms in Azerbaijan can't upload suspicious attachments to
public services like VirusTotal without a confidentiality problem. SOC analysts are scarce and
manual triage is slow. This tool runs entirely on one laptop, with no network calls, and gives
an analyst (or a small SME/university with no SOC budget) a first-pass verdict in seconds, with
every point of the score explained in plain language - not just a bare "Malicious: 87".

## Stack

- **Backend**: Python, FastAPI, `pefile`, `yara-python`, Jinja2
- **Frontend**: React + Vite + Tailwind CSS
- **Rules**: YARA (`backend/rules/generic`, `backend/rules/azerbaijan`)

## Project layout

```
backend/
  app/            # pipeline: PE parsing, strings, IOCs, YARA, ATT&CK, scoring, i18n, report
  rules/          # YARA rule packs (generic/ + azerbaijan/)
  templates/      # Jinja2 HTML report template (AZ/EN)
  samples/        # safe demo fixtures (no live malware)
  tests/          # pytest smoke tests + synthetic PE builder
frontend/
  src/
    components/   # UploadPanel, ReportView, ScoreBadge
    lib/          # api.js, stix.js, i18n.js
docs/
  TIMETABLE.md       # the 24h plan we followed
  ARCHITECTURE.md    # current + planned (capstone) architecture
  PDF_OUTLINE.md     # submission PDF skeleton, one section per rubric criterion
  DEMO_SCRIPT.md     # ~3 minute live demo script
```

## Running it

**Backend** (Windows, PowerShell):

```powershell
cd backend
py -3.13 -m venv venv
.\venv\Scripts\python.exe -m pip install --only-binary=yara-python -r requirements.txt
.\venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8002 --no-server-header
```

Health check: `http://127.0.0.1:8002/api/health` should report `"yara": {"available": true}`.
**Use Python 3.13** - `yara-python` 4.5.4 has no prebuilt wheel for 3.14 yet, and without YARA
the suspicious demo sample only scores 39/100 (the pipeline still runs, but the demo and
`test_synthetic_suspicious_sample_scores_high` fail). `venv` folders are machine-specific:
never copy one between computers, recreate it.

**Tests**:

```powershell
cd backend
.\venv\Scripts\python.exe -m pytest tests -v
```

**Frontend**:

```powershell
cd frontend
npm install
Copy-Item .env.example .env   # VITE_API_BASE=http://127.0.0.1:8002
npm run dev
```

Open the printed localhost URL. Two bundled demo samples are one click away in the UI -
a clean Windows system binary and a hand-built synthetic "suspicious" PE (see
[Test samples](#test-samples)) - so the demo never depends on a live network upload.

## API

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/health` | GET | liveness + whether the YARA engine compiled |
| `/api/analyze` | POST (multipart `file`) | full JSON report |
| `/api/analyze-sample?name=` | POST | same, for a bundled sample file |
| `/api/report/html?lang=en\|az` | POST (multipart `file`) | rendered HTML report |
| `/api/report/html-sample?name=&lang=` | POST | same, for a bundled sample |
| `/api/samples` | GET | list bundled demo sample filenames |

### JSON report shape

```jsonc
{
  "file": {"name": "", "size": 0, "md5": "", "sha1": "", "sha256": "", "imphash": ""},
  "pe": {"is_pe": true,
         "headers": {"machine": "x64 (64-bit)", "file_type": "EXE", "compile_time": "ISO-8601 or null",
                     "timestamp_raw": 0, "entry_point": "0x19c0", "image_base": "0x140000000",
                     "subsystem": "Windows GUI", "linker_version": "14.38", "number_of_sections": 8,
                     "aslr": true, "high_entropy_va": true, "dep": true, "cfg": true,
                     "embedded_signature": false},
         "sections": [{"name": "", "raw_size": 0, "virtual_size": 0, "entropy": 0.0}],
         "imports": {"KERNEL32.dll": ["..."]},
         "suspicious_imports": [{"api": "CreateRemoteThread", "dll": "KERNEL32.dll", "category": "injection"}],
         "anomalies": [{"type": "", "detail": ""}]},
  "strings": {"total": 0, "ascii": 0, "wide": 0,
              "interesting": {"registry": [], "autorun_registry": [], "mutexes": [],
                              "paths": [], "commands": [], "user_agents": []}},
  "yara": [{"rule": "", "namespace": "", "severity": "", "tags": [], "description": ""}],
  "iocs": {"urls": [], "domains": [], "ips": [], "private_ips": [],
           "hashes": {"md5": [], "sha1": [], "sha256": []}, "az_related": [],
           "registry_keys": [], "mutexes": []},
  "attack": [{"technique": "T1055", "name": "", "confidence": "high", "reason": ""}],
  "score": {"value": 0, "verdict": "Clean|Suspicious|Likely Malicious|Malicious", "reasons": ["+30 ..."]},
  "generated_at": "..."
}
```

All IOCs are defanged (`hxxp://`, `[.]`) before they ever reach the UI or a report.

## Test samples

No live malware is handled anywhere in this repo. Two fixtures live in `backend/samples/`:

- `clean_sample.exe` - a copy of a real Windows system binary, used to prove the pipeline does
  **not** false-positive on legitimate software (see `backend/tests/test_pipeline.py`). This is
  the exact check judges are told to look for. **Not committed to git** - it's a copy of a
  Microsoft binary, not ours to redistribute. Each teammate creates their own local copy; see
  `backend/samples/README.md` for the one-line command.
- `synthetic_suspicious.exe` - a hand-crafted, inert PE built by
  `backend/tests/make_synthetic_pe.py` (pure Python, no compiler needed). It imports the three
  process-injection APIs (`VirtualAllocEx` / `WriteProcessMemory` / `CreateRemoteThread`)
  *without ever calling them*, and embeds decoy strings: a fake C2 URL, a fake IP, an
  Azerbaijani-government-lookalike domain string, Azerbaijani finance/ministry lure keywords,
  and the industry-standard EICAR test string. It does nothing at runtime.

`backend/samples/make_test_sample.c` is also provided if your team has MinGW/MSVC available and
wants a real compiled-and-UPX-packed binary for the entropy/packer part of the demo - see the
comment header in that file for the two build commands.

## Security

The tool accepts hostile files by design, so the service itself is hardened
(`backend/app/security.py`, regression tests in `backend/tests/test_security.py`):

| Threat | Mitigation |
|---|---|
| Other websites calling the local API from the analyst's browser | CORS allowlist (frontend origins only), no credentials |
| DNS rebinding (attacker domain resolving to 127.0.0.1) | `Host` header allowlist (`TrustedHostMiddleware`) |
| Accidental LAN exposure | Backend and Vite bind to `127.0.0.1` by default |
| Huge / chunked uploads exhausting memory or disk | Streaming body-size limit (50MB) enforced before parsing, 413 response |
| CPU exhaustion | Analysis off the event loop, max 2 concurrent analyses (503 when busy), per-IP rate limit (30/min, 429), YARA scan timeout |
| ReDoS in IOC regexes (a 32KB string used to take 40s) | Domain matching only on bounded hostname tokens, URL length cap - now linear |
| Report flooding (millions of fake IOCs) | Max 500 IOCs per type; section/import counts and name lengths capped |
| XSS via strings from the sample (filenames, section names, IOCs) | React/Jinja2 auto-escaping, control-char stripping, filename sanitising, strict CSP on the app, the API and the saved HTML report (no scripts at all) |
| Path traversal on bundled samples | Strict name pattern + `commonpath` check, `.exe`/`.dll` only |
| STIX pattern injection into MISP/TheHive | IOC values escaped inside STIX patterns, crypto-random IDs |
| Information leakage | Generic 500 errors (details only in server log), `/docs` disabled, no `Server` header, `Cache-Control: no-store`, `Referrer-Policy: no-referrer` |
| Clickjacking / sniffing | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff` |
| Vulnerable dependencies | All pins `pip-audit` / `npm audit` clean; re-run before every release |
| Unauthorized use of a shared deployment | Optional `IOCTOPUS_API_KEY` (`X-API-Key` header, constant-time compare) |

Settings are environment variables - see `backend/.env.example`. To expose the backend on a
LAN on purpose: `--host 0.0.0.0`, add the IP to `IOCTOPUS_ALLOWED_HOSTS` and the frontend URL to
`IOCTOPUS_ALLOWED_ORIGINS`, and set `IOCTOPUS_API_KEY`.

Dependency audit:

```powershell
.\venv\Scripts\python.exe -m pip install pip-audit
.\venv\Scripts\python.exe -m pip_audit -r requirements.txt
cd ..\frontend; npm audit
```

**Handling samples safely**: uploads are analyzed in memory and never executed; temp spool
files are closed immediately. Still, analyze real malware only inside an isolated VM, and
expect Windows Defender to quarantine live samples placed in `backend/samples/`.

## Known limitations (be upfront about these in the PDF and demo)

- Static analysis only - a sufficiently motivated packer/obfuscator can defeat all of this.
- Windows PE files only; no ELF/Mach-O, no script-based malware (macros, PowerShell, JS).
- No sandbox/behavioral analysis in this build - that's the planned capstone extension.
- YARA/ATT&CK/IOC heuristics are only as good as the rules and API lists behind them; they're
  tuned to minimize false positives on legitimate Windows binaries, not to catch everything.
- The TLD list used for domain validation is a curated subset, not the full IANA root zone.

## Capstone roadmap (next steps beyond the hackathon)

1. CAPEv2 (or similar) sandbox integration for real dynamic/behavioral analysis.
2. Mutex, registry and network-behavior IOC extraction from sandbox runs.
3. Analyst case queue + dashboard (the static engine becomes one stage of a bigger pipeline).
4. TheHive / MISP integration for case management and IOC sharing with CERT.AZ.
5. ISO 27001:2022 evidence-trail tooling (5.25-5.26 assessment/response, 5.28 evidence
   collection) built on the hash + timestamp data this tool already produces.
