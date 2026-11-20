"""Compile and run the YARA rule packs. Degrades gracefully if yara-python
or the rules directory is unavailable, so the rest of the pipeline keeps working."""
import logging
import os

try:
    import yara
except ImportError:
    yara = None

logger = logging.getLogger("gozetci.yara")

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")

# Hard stop for a single scan, so a pathological file can't pin a CPU forever.
SCAN_TIMEOUT_SECONDS = 20

_compiled = None
_compile_error = None


def _collect_rule_files() -> dict:
    sources = {}
    for root, _dirs, files in os.walk(RULES_DIR):
        for f in files:
            if f.endswith((".yar", ".yara")):
                path = os.path.join(root, f)
                namespace = os.path.splitext(f)[0]
                sources[namespace] = path
    return sources


def get_compiled_rules():
    global _compiled, _compile_error
    if _compiled is not None or _compile_error is not None:
        return _compiled
    if yara is None:
        _compile_error = "yara-python not installed"
        return None
    sources = _collect_rule_files()
    if not sources:
        _compile_error = "no rule files found"
        return None
    try:
        _compiled = yara.compile(filepaths=sources)
    except Exception as exc:
        _compile_error = str(exc)
        _compiled = None
        logger.error("YARA rules failed to compile: %s", exc)
    return _compiled


def scan_bytes(data: bytes) -> list:
    rules = get_compiled_rules()
    if rules is None:
        return []
    try:
        matches = rules.match(data=data, timeout=SCAN_TIMEOUT_SECONDS)
    except Exception:
        logger.warning("YARA scan failed or timed out", exc_info=True)
        return []
    results = []
    for m in matches:
        severity = m.meta.get("severity", "medium") if hasattr(m, "meta") else "medium"
        results.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "severity": severity,
            "tags": list(m.tags),
            "description": m.meta.get("description", "") if hasattr(m, "meta") else "",
        })
    return results


def engine_status() -> dict:
    get_compiled_rules()
    return {"available": _compiled is not None, "error": _compile_error}
