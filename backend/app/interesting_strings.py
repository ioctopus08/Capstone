"""Pick the strings an analyst actually wants to read out of the thousands a
binary contains: registry keys, mutex / named-object names, file paths,
suspicious command lines and HTTP user-agents.

Registry keys and mutexes are also surfaced as static IOCs. Sandbox runs (the
capstone extension) will add the ones only visible at runtime.

Every pattern uses bounded, non-nested quantifiers and runs on strings that
are cut to MAX_SCAN_LEN, so a hostile file can't trigger regex backtracking
blow-ups (see the ReDoS note in ioc_extract.py).
"""
import re

MAX_SCAN_LEN = 1024
MAX_ITEM_LEN = 300
MAX_PER_CATEGORY = 100

REGISTRY_RE = re.compile(
    r"(?:\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU)\\"
    r"|\b(?:SOFTWARE|SYSTEM)\\(?:Microsoft|Policies|CurrentControlSet|Classes|WOW6432Node)\\)"
    r"[^\x00-\x1f\"'<>|]{1,250}",
    re.IGNORECASE,
)

# Keys malware commonly writes to so it survives a reboot (ATT&CK T1547 / T1543).
AUTORUN_MARKERS = (
    "\\currentversion\\run", "\\currentversion\\runonce", "\\currentversion\\winlogon",
    "\\currentversion\\policies\\explorer\\run", "\\image file execution options",
    "\\currentcontrolset\\services\\", "\\currentversion\\explorer\\shell folders",
)

# Named kernel objects: "Global\..." / "Local\..." / "Session\N\...". Most are
# mutexes; events and sections use the same namespaces.
MUTEX_RE = re.compile(r"^(?:Global|Local|Session\\[0-9]{1,3})\\[A-Za-z0-9_.{}\-]{3,120}$")

PATH_RE = re.compile(
    r"(?:\b[A-Za-z]:\\|%[A-Za-z_]{2,24}%\\|\\\\\?\\)[^\x00-\x1f\"'<>|*?]{2,200}"
)

# Living-off-the-land binaries and command fragments seen in droppers/loaders.
COMMAND_MARKERS = (
    "cmd.exe /c", "cmd /c", "powershell", "-encodedcommand", " -enc ", "invoke-expression", "iex(",
    "downloadstring", "downloadfile", "frombase64string", "schtasks", "reg add", "reg delete",
    "vssadmin", "wmic ", "bcdedit", "rundll32", "regsvr32", "mshta", "certutil", "bitsadmin",
    "net user", "net localgroup", "whoami", "taskkill", "attrib +h", "wevtutil cl",
)

USER_AGENT_RE = re.compile(r"\bMozilla/[0-9]\.[0-9][^\x00-\x1f]{0,250}")


def _add(bucket: list, seen: set, value: str):
    value = value.strip()[:MAX_ITEM_LEN]
    key = value.lower()
    if value and key not in seen and len(bucket) < MAX_PER_CATEGORY:
        seen.add(key)
        bucket.append(value)


def extract_interesting_strings(strings: list) -> dict:
    registry, mutexes, paths, commands, user_agents = [], [], [], [], []
    seen = {name: set() for name in ("registry", "mutexes", "paths", "commands", "user_agents")}
    autorun = []

    for raw in strings:
        s = raw[:MAX_SCAN_LEN]
        lower = s.lower()

        for m in REGISTRY_RE.finditer(s):
            key = m.group().rstrip("\\ ")
            _add(registry, seen["registry"], key)
            if any(marker in key.lower() for marker in AUTORUN_MARKERS) and key not in autorun:
                autorun.append(key[:MAX_ITEM_LEN])

        if MUTEX_RE.match(s):
            _add(mutexes, seen["mutexes"], s)

        for m in PATH_RE.finditer(s):
            _add(paths, seen["paths"], m.group())

        if any(marker in lower for marker in COMMAND_MARKERS):
            _add(commands, seen["commands"], s)

        for m in USER_AGENT_RE.finditer(s):
            _add(user_agents, seen["user_agents"], m.group())

    return {
        "registry": sorted(registry, key=str.lower),
        "autorun_registry": autorun[:MAX_PER_CATEGORY],
        "mutexes": sorted(mutexes, key=str.lower),
        "paths": sorted(paths, key=str.lower),
        "commands": commands,
        "user_agents": user_agents,
    }
