"""Static PE parsing: hashes, sections, imports, anomalies."""
import hashlib
import logging
import math
import re
import time
from collections import Counter

try:
    import pefile
except ImportError:
    pefile = None

UPX_SECTION_NAMES = {"upx0", "upx1", "upx2", ".upx0", ".upx1"}

# API groups that together indicate a known ATT&CK technique.
INJECTION_APIS = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
PERSISTENCE_APIS = {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"}
ANTI_DEBUG_APIS = {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"}
NETWORK_APIS = {"InternetOpenA", "InternetOpenUrlA", "URLDownloadToFileA", "WinHttpOpen", "send", "recv", "connect"}
KEYLOG_APIS = {"GetAsyncKeyState", "GetKeyState", "SetWindowsHookExA", "SetWindowsHookExW"}

logger = logging.getLogger("gozetci.pe")

# Names inside a hostile PE are attacker-controlled: strip control characters
# and bound their length/count before they reach the JSON/HTML report.
_UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f]")
MAX_NAME_LEN = 128
MAX_SECTIONS = 96          # the PE format itself caps NumberOfSections at 96 for loaders
MAX_DLLS = 256
MAX_IMPORTS_PER_DLL = 2048


def clean_name(raw: bytes) -> str:
    return _UNSAFE_CHARS.sub("", raw.decode(errors="replace"))[:MAX_NAME_LEN]


def file_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    # Counter's byte counting runs in C - the old pure-Python loop over a
    # 50MB section was slow enough to be a cheap CPU-exhaustion vector.
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def analyze_pe(data: bytes) -> dict:
    """Returns {sections, imports, anomalies, imphash, is_pe} - never raises."""
    try:
        return _analyze_pe(data)
    except Exception:
        # Malformed-on-purpose samples must never crash the request.
        logger.exception("PE analysis failed")
        return {
            "is_pe": False, "sections": [], "imports": {}, "imphash": None,
            "anomalies": [{"type": "not_a_pe", "detail": "PE structure could not be parsed (malformed or truncated)"}],
        }


def _analyze_pe(data: bytes) -> dict:
    result = {"is_pe": False, "sections": [], "imports": {}, "anomalies": [], "imphash": None}

    if pefile is None:
        result["anomalies"].append({"type": "engine_unavailable", "detail": "pefile not installed"})
        return result

    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
        ])
    except Exception:
        # Don't echo parser internals back to the client.
        result["anomalies"].append({"type": "not_a_pe", "detail": "Not a valid Windows PE file"})
        return result

    result["is_pe"] = True

    try:
        result["imphash"] = pe.get_imphash()
    except Exception:
        result["imphash"] = None

    for section in pe.sections[:MAX_SECTIONS]:
        name = clean_name(section.Name.rstrip(b"\x00"))
        raw_data = section.get_data()
        entropy = shannon_entropy(raw_data)
        entry = {
            "name": name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": entropy,
        }
        result["sections"].append(entry)

        if entropy > 7.2:
            result["anomalies"].append({
                "type": "high_entropy_section",
                "detail": f"Section {name} entropy {entropy} (>7.2 suggests packing/encryption)",
            })
        if name.lower() in UPX_SECTION_NAMES:
            result["anomalies"].append({
                "type": "packer_signature",
                "detail": f"Section name '{name}' matches known UPX packer layout",
            })
        # File-alignment padding routinely makes raw_size > virtual_size - that's
        # normal and not flagged. A section whose in-memory size is much larger
        # than what's stored on disk (data expands only once loaded) is the
        # suspicious direction, typical of packers/decompression stubs.
        if section.SizeOfRawData > 0 and section.Misc_VirtualSize > section.SizeOfRawData * 3:
            result["anomalies"].append({
                "type": "size_mismatch",
                "detail": f"Section {name} is much larger in memory than on disk (virtual={section.Misc_VirtualSize}, raw={section.SizeOfRawData}) - may unpack/decompress at runtime",
            })

    # Imports grouped by DLL, flattened API name set for technique matching
    all_apis = set()
    imports_by_dll = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT[:MAX_DLLS]:
            dll = clean_name(entry.dll) if entry.dll else "unknown"
            names = []
            for imp in entry.imports[:MAX_IMPORTS_PER_DLL]:
                if imp.name:
                    api_name = clean_name(imp.name)
                    names.append(api_name)
                    all_apis.add(api_name)
            imports_by_dll.setdefault(dll, []).extend(names)
    result["imports"] = imports_by_dll
    result["_all_apis"] = sorted(all_apis)

    if not all_apis:
        result["anomalies"].append({
            "type": "no_imports",
            "detail": "No imported APIs found - unusual for legitimate software, common in shellcode loaders",
        })

    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
        if timestamp > time.time() + 86400:
            result["anomalies"].append({
                "type": "future_timestamp",
                "detail": f"Compile timestamp {timestamp} is in the future",
            })
        if timestamp == 0:
            result["anomalies"].append({
                "type": "zero_timestamp",
                "detail": "Compile timestamp is zero (often stripped/anonymized)",
            })
    except Exception:
        pass

    if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS is not None:
        result["anomalies"].append({
            "type": "tls_callback",
            "detail": "TLS callback table present - can execute code before main entry point",
        })

    try:
        pe.close()
    except Exception:
        pass

    return result
