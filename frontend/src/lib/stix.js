// Minimal STIX 2.1 bundle built client-side from an analysis report's IOCs,
// so results can be shared with national CERT / SOC tooling (MISP, TheHive).

// Cryptographically secure IDs (Math.random() is predictable and can collide).
function uuidv4() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  const b = globalThis.crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// IOC values come from a hostile file. STIX pattern string literals are
// single-quoted; an unescaped ' or \ would let a sample inject extra pattern
// logic into whatever MISP/TheHive instance ingests this bundle.
function stixString(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

const HEX64 = /^[a-f0-9]{64}$/i;

function indicator(pattern, description, now, types = ["malicious-activity"]) {
  return {
    type: "indicator",
    spec_version: "2.1",
    id: `indicator--${uuidv4()}`,
    created: now,
    modified: now,
    name: description.slice(0, 120),
    pattern,
    pattern_type: "stix",
    valid_from: now,
    indicator_types: types,
    description,
  };
}

// Reverses the report's hxxp/[.] defanging back to real syntax for the pattern value.
function refang(s) {
  return String(s).replace(/hxxps:\/\//gi, "https://").replace(/hxxp:\/\//gi, "http://").replace(/\[\.\]/g, ".");
}

export function buildStixBundle(report) {
  const now = new Date().toISOString();
  const objects = [];
  const iocs = report.iocs || {};
  // A file the triage judged Clean must not push its strings (e.g. its own
  // settings registry key) into a CERT feed labelled as malicious.
  const types = report.score?.verdict === "Clean" ? ["unknown"] : ["malicious-activity"];
  const add = (pattern, description) => objects.push(indicator(pattern, description, now, types));

  for (const url of iocs.urls || []) {
    add(`[url:value = '${stixString(refang(url))}']`, "URL observed in sample strings");
  }
  for (const domain of iocs.domains || []) {
    add(`[domain-name:value = '${stixString(refang(domain))}']`, "Domain observed in sample strings");
  }
  for (const ip of iocs.ips || []) {
    add(`[ipv4-addr:value = '${stixString(ip)}']`, "Public IP observed in sample strings");
  }
  for (const key of iocs.registry_keys || []) {
    add(`[windows-registry-key:key = '${stixString(key)}']`, "Registry key observed in sample strings");
  }
  for (const name of iocs.mutexes || []) {
    add(`[mutex:name = '${stixString(name)}']`, "Mutex / named object observed in sample strings");
  }
  for (const sha256 of iocs.hashes?.sha256 || []) {
    if (!HEX64.test(sha256)) continue;
    add(`[file:hashes.'SHA-256' = '${sha256}']`, "SHA-256 found inside sample (embedded reference hash)");
  }

  // One indicator for the analyzed file itself; YARA hits go in its description
  // instead of duplicating the same hash pattern once per rule.
  const fileHash = report.file?.sha256;
  if (fileHash && HEX64.test(fileHash)) {
    const rules = (report.yara || []).map((y) => y.rule).filter(Boolean);
    const verdict = report.score ? ` - verdict ${report.score.verdict} (${report.score.value}/100)` : "";
    const yaraNote = rules.length ? `; YARA: ${rules.join(", ")}` : "";
    add(`[file:hashes.'SHA-256' = '${fileHash}']`, `Analyzed sample ${report.file.name}${verdict}${yaraNote}`);
  }

  return {
    type: "bundle",
    id: `bundle--${uuidv4()}`,
    objects,
  };
}

// Filenames in reports are derived from the analyzed file's name: keep only
// safe characters so a crafted name can't produce odd/hidden download names.
export function safeDownloadName(name, fallback = "report") {
  const cleaned = String(name || "")
    .replace(/[^A-Za-z0-9._-]+/g, "_")
    .replace(/^[._]+/, "")
    .slice(0, 100);
  return cleaned || fallback;
}

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function downloadJson(obj, filename) {
  downloadBlob(new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" }), filename);
}
