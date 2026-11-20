import asyncio
import datetime
import logging
import os
from typing import Literal

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from app.attack_mapping import map_attack_techniques
from app.ioc_extract import extract_iocs
from app.pe_analysis import analyze_pe, file_hashes
from app.report import render_html_report
from app.scoring import compute_score
from app.security import (
    SAMPLE_NAME_PATTERN,
    BodySizeLimitMiddleware,
    SecurityHeadersMiddleware,
    analysis_slots,
    enforce_rate_limit,
    require_api_key,
    sanitize_filename,
    settings,
)
from app.strings_extract import extract_strings
from app.yara_scan import engine_status, scan_bytes

logger = logging.getLogger("ioctopus")

app = FastAPI(
    title="IOCtopus Static Triage API",
    version="0.2.0",
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)

# Order matters: the last middleware added runs first on a request.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
    max_age=600,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_upload_bytes)
app.add_middleware(SecurityHeadersMiddleware)

MAX_UPLOAD_BYTES = settings.max_upload_bytes
SAMPLES_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "samples"))
SAMPLE_EXTENSIONS = (".exe", ".dll")

# Every analysis endpoint: optional API key, then per-IP rate limit.
analysis_guards = [Depends(require_api_key), Depends(enforce_rate_limit)]


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Log the detail server-side, never return stack traces / internals to the client.
    logger.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal error while analyzing the file"})


def build_report(filename: str, data: bytes) -> dict:
    hashes = file_hashes(data)
    pe_result = analyze_pe(data)
    strings = extract_strings(data)
    iocs = extract_iocs(strings["all"])
    yara_matches = scan_bytes(data)
    attack_findings = map_attack_techniques(pe_result.get("_all_apis", []))
    score = compute_score(pe_result, yara_matches, attack_findings, iocs)

    pe_public = {k: v for k, v in pe_result.items() if not k.startswith("_")}

    return {
        "file": {
            "name": sanitize_filename(filename),
            "size": len(data),
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "sha256": hashes["sha256"],
            "imphash": pe_result.get("imphash"),
        },
        "pe": pe_public,
        "yara": yara_matches,
        "iocs": iocs,
        "attack": attack_findings,
        "score": score,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


async def run_analysis(filename: str, data: bytes) -> dict:
    """Runs the CPU-heavy pipeline off the event loop, with a cap on how many
    analyses run at once so a burst of uploads can't exhaust the machine."""
    try:
        await asyncio.wait_for(analysis_slots.acquire(), timeout=settings.queue_timeout_seconds)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=503, detail="Analyzer busy - try again shortly", headers={"Retry-After": "10"})
    try:
        report = await run_in_threadpool(build_report, filename, data)
    finally:
        analysis_slots.release()
    # Audit trail: what was analyzed and the verdict (never the file content).
    logger.info("analyzed sha256=%s size=%d score=%s", report["file"]["sha256"], report["file"]["size"], report["score"]["value"])
    return report


async def read_upload(file: UploadFile) -> bytes:
    try:
        data = await file.read(MAX_UPLOAD_BYTES + 1)
    finally:
        await file.close()  # removes any spooled temp copy of the (possibly malicious) upload
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)}MB)")
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    return data


def read_sample(name: str) -> tuple:
    safe_name = os.path.basename(name)
    if not safe_name.lower().endswith(SAMPLE_EXTENSIONS):
        raise HTTPException(status_code=404, detail="Sample not found")
    path = os.path.realpath(os.path.join(SAMPLES_DIR, safe_name))
    # commonpath (not startswith) so "samples_evil/" can't pass as "samples/".
    if os.path.commonpath([path, SAMPLES_DIR]) != SAMPLES_DIR or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Sample not found")
    if os.path.getsize(path) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Sample too large")
    with open(path, "rb") as f:
        return safe_name, f.read()


SampleName = Query(..., pattern=SAMPLE_NAME_PATTERN, max_length=100)
ReportLang = Query("en")


@app.get("/api/health")
def health():
    return {"status": "ok", "yara": {"available": engine_status()["available"]}}


@app.post("/api/analyze", dependencies=analysis_guards)
async def analyze(file: UploadFile = File(...)):
    data = await read_upload(file)
    return await run_analysis(file.filename, data)


@app.get("/api/samples", dependencies=[Depends(require_api_key)])
def list_samples():
    if not os.path.isdir(SAMPLES_DIR):
        return []
    names = [
        f for f in os.listdir(SAMPLES_DIR)
        if f.lower().endswith(SAMPLE_EXTENSIONS) and os.path.isfile(os.path.join(SAMPLES_DIR, f))
    ]
    return sorted(names)


@app.post("/api/analyze-sample", dependencies=analysis_guards)
async def analyze_sample(name: str = SampleName):
    safe_name, data = read_sample(name)
    return await run_analysis(safe_name, data)


@app.post("/api/report/html", response_class=HTMLResponse, dependencies=analysis_guards)
async def analyze_html(file: UploadFile = File(...), lang: Literal["en", "az"] = ReportLang):
    data = await read_upload(file)
    report = await run_analysis(file.filename, data)
    return HTMLResponse(content=render_html_report(report, lang=lang))


@app.post("/api/report/html-sample", response_class=HTMLResponse, dependencies=analysis_guards)
async def analyze_html_sample(name: str = SampleName, lang: Literal["en", "az"] = ReportLang):
    safe_name, data = read_sample(name)
    report = await run_analysis(safe_name, data)
    return HTMLResponse(content=render_html_report(report, lang=lang))
