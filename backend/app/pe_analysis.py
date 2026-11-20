"""Static PE parsing: hashes, header metadata, sections, imports, anomalies."""
import datetime
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
EXECUTION_APIS = {"WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW"}

# Display-only tagging of imports worth an analyst's eye. Deliberately NOT
# scored here - scoring stays in attack_mapping/scoring, which weigh API
# *combinations* so ordinary software isn't penalised for one common API.
SUSPICIOUS_API_CATEGORIES = {}
for _category, _apis in (
    ("injection", INJECTION_APIS),
    ("persistence", PERSISTENCE_APIS),
    ("anti-debug", ANTI_DEBUG_APIS),
    ("network", NETWORK_APIS),
    ("keylogging", KEYLOG_APIS),
    ("execution", EXECUTION_APIS),
):
    for _api in _apis:
        SUSPICIOUS_API_CATEGORIES[_api] = _category

MACHINE_TYPES = {0x14C: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0x1C4: "ARM", 0xAA64: "ARM64", 0x200: "IA-64"}
SUBSYSTEMS = {
    1: "Native (driver)", 2: "Windows GUI", 3: "Windows console", 5: "OS/2 console", 7: "POSIX console",
    9: "Windows CE GUI", 10: "EFI application", 11: "EFI boot driver", 12: "EFI runtime driver",
    14: "Xbox", 16: "Windows boot application",
}
DLLCHAR_HIGH_ENTROPY_VA = 0x0020
DLLCHAR_ASLR = 0x0040
DLLCHAR_DEP = 0x0100
DLLCHAR_CFG = 0x4000
FILECHAR_DLL = 0x2000
SECURITY_DIRECTORY_INDEX = 4

logger = logging.getLogger("ioctopus.pe")

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
            "is_pe": False, "headers": None, "sections": [], "imports": {},
            "suspicious_imports": [], "imphash": None,
            "anomalies": [{"type": "not_a_pe", "detail": "PE structure could not be parsed (malformed or truncated)"}],
        }


def extract_headers(pe) -> dict:
    """The PE 'passport': what kind of binary this is and how Windows loads it."""
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    timestamp = fh.TimeDateStamp
    compile_time = None
    if timestamp:
        try:
            compile_time = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            compile_time = None
    dll_chars = getattr(oh, "DllCharacteristics", 0) or 0

    signed = False
    try:
        directories = oh.DATA_DIRECTORY
        if len(directories) > SECURITY_DIRECTORY_INDEX:
            sec = directories[SECURITY_DIRECTORY_INDEX]
            signed = bool(sec.VirtualAddress and sec.Size)
    except Exception:
        signed = False

    return {
        "machine": MACHINE_TYPES.get(fh.Machine, f"Unknown (0x{fh.Machine:x})"),
        "file_type": "DLL" if fh.Characteristics & FILECHAR_DLL else "EXE",
        "compile_time": compile_time,
        "timestamp_raw": timestamp,
        "entry_point": f"0x{oh.AddressOfEntryPoint:x}",
        "image_base": f"0x{oh.ImageBase:x}",
        "subsystem": SUBSYSTEMS.get(oh.Subsystem, f"Unknown ({oh.Subsystem})"),
        "linker_version": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
        "number_of_sections": fh.NumberOfSections,
        "aslr": bool(dll_chars & DLLCHAR_ASLR),
        "high_entropy_va": bool(dll_chars & DLLCHAR_HIGH_ENTROPY_VA),
        "dep": bool(dll_chars & DLLCHAR_DEP),
        "cfg": bool(dll_chars & DLLCHAR_CFG),
        # Embedded Authenticode only. Windows system files are usually
        # catalog-signed instead, so "False" here is informational, never scored.
        "embedded_signature": signed,
    }


def _analyze_pe(data: bytes) -> dict:
    result = {
        "is_pe": False, "headers": None, "sections": [], "imports": {},
        "suspicious_imports": [], "anomalies": [], "imphash": None,
    }

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
        result["headers"] = extract_headers(pe)
    except Exception:
        logger.warning("PE header extraction failed", exc_info=True)
        result["headers"] = None

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
                    category = SUSPICIOUS_API_CATEGORIES.get(api_name)
                    if category:
                        result["suspicious_imports"].append({"api": api_name, "dll": dll, "category": category})
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
