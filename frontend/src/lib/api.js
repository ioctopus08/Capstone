// Default matches the README's documented backend port.
const API_BASE = (import.meta.env.VITE_API_BASE || "http://127.0.0.1:8002").replace(/\/+$/, "");
// Optional - only for a shared deployment where the backend sets IOCTOPUS_API_KEY.
// Note: anything in VITE_* is embedded in the built JS bundle, so this is a
// light access control for a trusted LAN, not a secret against bundle readers.
const API_KEY = import.meta.env.VITE_API_KEY || "";

export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 120_000;

async function request(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const headers = { ...(options.headers || {}) };
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
      signal: controller.signal,
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    if (!res.ok) throw new Error(await errorMessage(res));
    return res;
  } catch (e) {
    if (e.name === "AbortError") throw new Error("Request timed out");
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function errorMessage(res) {
  try {
    const body = await res.json();
    if (typeof body?.detail === "string") return `${body.detail} (${res.status})`;
  } catch {
    // non-JSON error body - fall through to the generic message
  }
  return `Request failed: ${res.status}`;
}

function assertUploadable(file) {
  if (!file || file.size === 0) throw new Error("Empty file");
  if (file.size > MAX_UPLOAD_BYTES) throw new Error("File too large (max 50MB)");
}

export async function analyzeFile(file) {
  assertUploadable(file);
  const form = new FormData();
  form.append("file", file);
  const res = await request("/api/analyze", { method: "POST", body: form });
  return res.json();
}

export async function analyzeSample(name) {
  const res = await request(`/api/analyze-sample?name=${encodeURIComponent(name)}`, { method: "POST" });
  return res.json();
}

export async function listSamples() {
  try {
    const res = await request("/api/samples");
    const data = await res.json();
    return Array.isArray(data) ? data.filter((n) => typeof n === "string") : [];
  } catch {
    return [];
  }
}

export async function fetchHtmlReport({ file, sampleName, lang }) {
  const safeLang = lang === "az" ? "az" : "en";
  let res;
  if (file) {
    assertUploadable(file);
    const form = new FormData();
    form.append("file", file);
    res = await request(`/api/report/html?lang=${safeLang}`, { method: "POST", body: form });
  } else {
    res = await request(
      `/api/report/html-sample?name=${encodeURIComponent(sampleName)}&lang=${safeLang}`,
      { method: "POST" }
    );
  }
  return res.text();
}

export { API_BASE };
