"""Extract printable ASCII and UTF-16LE ('wide') strings from raw bytes."""
import re

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
# A wide string is ASCII bytes separated by 0x00 - matches 'W\x00i\x00d\x00e\x00'
WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def extract_strings(data: bytes, min_len: int = 4) -> dict:
    ascii_strings = [m.group().decode("ascii", errors="ignore") for m in ASCII_RE.finditer(data)]

    wide_strings = []
    for m in WIDE_RE.finditer(data):
        try:
            decoded = m.group().decode("utf-16-le", errors="ignore")
            wide_strings.append(decoded)
        except Exception:
            continue

    ascii_strings = [s for s in ascii_strings if len(s) >= min_len]
    wide_strings = [s for s in wide_strings if len(s) >= min_len]

    return {
        "ascii": ascii_strings,
        "wide": wide_strings,
        "all": ascii_strings + wide_strings,
    }
