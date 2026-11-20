"""Extract and defang URLs, domains, IPs and hashes from strings, filtering noise."""
import ipaddress
import re
from urllib.parse import urlsplit

# Only real network schemes - excludes OS URI handlers like ms-windows-store://
# or feedback-hub:// that are routine in Windows binaries and not network IOCs.
URL_RE = re.compile(r"\b(?:https?|ftps?|wss?)://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# ReDoS protection: DOMAIN_RE backtracks quadratically on long dotted runs
# ("a.a.a.a..." - a 32KB string took 40s). Domain matching therefore only runs
# on hostname-shaped tokens no longer than a legal DNS name (253 chars), which
# bounds the work per token and keeps the whole scan linear in the input.
HOST_TOKEN_RE = re.compile(r"[A-Za-z0-9.-]{4,}")
MAX_HOSTNAME_LEN = 253
MAX_URL_LEN = 2048
# Caps output size so a file stuffed with millions of fake IOCs can't produce
# a gigantic JSON/HTML/STIX report (memory + browser DoS).
MAX_IOCS_PER_TYPE = 500

# Curated subset of real TLDs - swap for the full IANA root zone list in production.
VALID_TLDS = {
    "com", "net", "org", "info", "biz", "name", "pro", "io", "co", "dev", "app",
    "az", "ru", "tr", "uk", "us", "de", "fr", "cn", "jp", "kr", "in", "br", "ca",
    "au", "eu", "gov", "edu", "mil", "int", "online", "site", "xyz", "top", "icu",
    "club", "shop", "tech", "cloud", "store", "live", "life", "world", "link",
    "email", "work", "today", "news", "digital", "finance", "bank",
    "test", "example",  # RFC 2606 reserved - useful so our own demo samples resolve as domains too
}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]

# Common false-positive version-number style strings that look like IPv4.
VERSION_LOOKALIKES = {"1.0.0.1", "0.0.0.0", "255.255.255.0", "255.255.255.255", "127.0.0.1"}

# Ubiquitous, well-known vendor/schema infrastructure that shows up in almost
# every legitimate Windows binary's string table (XML namespaces, OS vendor
# telemetry/help links, standards bodies). Treated as noise, not an IOC -
# without this, every clean system binary scores as "malicious".
KNOWN_BENIGN_DOMAIN_SUFFIXES = (
    "microsoft.com", "windows.com", "windowsupdate.com", "msn.com", "live.com",
    "schemas.openxmlformats.org", "schemas.microsoft.com", "w3.org", "xml.org",
    "verisign.com", "digicert.com", "sectigo.com", "globalsign.com",
    "apple.com", "google.com", "mozilla.org", "adobe.com",
)


def is_known_benign_domain(domain: str) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in KNOWN_BENIGN_DOMAIN_SUFFIXES)


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


def is_version_lookalike(ip: str) -> bool:
    """Catches file/product version strings like '5.1.0.0' or '6.0.0.0' that
    regex-match IPv4 but are not addresses - real hosts almost never end in
    two trailing zero octets, but version numbers commonly do."""
    octets = ip.split(".")
    return octets[-1] == "0" and octets[-2] == "0"


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    octets = ip.split(".")
    # Reject things like 999.999.999.999 or version-like 1.2.3.4 with leading zeros patterns
    if any(len(o) > 1 and o.startswith("0") for o in octets):
        return False
    if is_version_lookalike(ip):
        return False
    return True


def has_valid_tld(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld in VALID_TLDS


def defang(ioc: str) -> str:
    return ioc.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def iter_domain_candidates(s: str):
    for token in HOST_TOKEN_RE.finditer(s):
        tok = token.group()
        if len(tok) > MAX_HOSTNAME_LEN:
            continue
        for m in DOMAIN_RE.finditer(tok):
            yield m.group()


def url_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _capped(items, transform=None) -> list:
    out = sorted(items)[:MAX_IOCS_PER_TYPE]
    return [transform(x) for x in out] if transform else out


def extract_iocs(strings: list) -> dict:
    urls, domains, ips, private_ips = set(), set(), set(), set()
    md5s, sha1s, sha256s = set(), set(), set()

    for s in strings:
        for m in URL_RE.finditer(s):
            url = m.group()
            if len(url) > MAX_URL_LEN:
                continue
            host = url_host(url)
            if host and is_known_benign_domain(host):
                continue
            urls.add(url)
        for m in IP_RE.finditer(s):
            candidate = m.group()
            if candidate in VERSION_LOOKALIKES or not is_valid_ip(candidate):
                continue
            if is_private_ip(candidate):
                private_ips.add(candidate)
            else:
                ips.add(candidate)
        for candidate in iter_domain_candidates(s):
            candidate = candidate.lower()
            if has_valid_tld(candidate) and not IP_RE.fullmatch(candidate) and not is_known_benign_domain(candidate):
                domains.add(candidate)
        for m in SHA256_RE.finditer(s):
            sha256s.add(m.group().lower())
        for m in SHA1_RE.finditer(s):
            sha1s.add(m.group().lower())
        for m in MD5_RE.finditer(s):
            md5s.add(m.group().lower())

    # Avoid double counting hex strings matched by multiple hash lengths is not
    # possible here since lengths differ, but avoid overlap where a sha256 also
    # matches an md5 substring scan - not applicable with fullmatch-free regex,
    # kept simple for a 24h build.

    # Real .az TLD only - NOT a ".az" substring search, which also matches things
    # like "*.azureedge.net" or "*.azure.com" (Azure CDN/hosting, extremely common
    # in ordinary installers) and caused exactly that false positive on a Node.js
    # MSI during testing.
    def is_real_az_tld(host: str) -> bool:
        return host.rsplit(".", 1)[-1].lower() == "az"

    az_domains = {d for d in domains if is_real_az_tld(d)}
    az_urls = set()
    for u in urls:
        host = url_host(u)
        if host and is_real_az_tld(host):
            az_urls.add(u)
    az_related = az_domains | az_urls

    return {
        "urls": _capped(urls, defang),
        "domains": _capped(domains, defang),
        "ips": _capped(ips),
        "private_ips": _capped(private_ips),
        "hashes": {
            "md5": _capped(md5s),
            "sha1": _capped(sha1s),
            "sha256": _capped(sha256s),
        },
        "az_related": _capped(az_related, defang),
    }
