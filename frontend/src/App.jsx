import { useEffect, useState } from "react";
import UploadPanel from "./components/UploadPanel";
import ReportView from "./components/ReportView";
import { analyzeFile, analyzeSample, listSamples, fetchHtmlReport } from "./lib/api";
import { buildStixBundle, downloadBlob, downloadJson, safeDownloadName } from "./lib/stix";
import { UI } from "./lib/i18n";

export default function App() {
  const [lang, setLang] = useState("en");
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [samples, setSamples] = useState([]);
  const [lastSource, setLastSource] = useState(null); // { file } or { sampleName }

  const t = UI[lang];

  useEffect(() => {
    listSamples().then(setSamples).catch(() => setSamples([]));
  }, []);

  async function handleFile(file) {
    setLoading(true);
    setError(null);
    setLastSource({ file });
    try {
      const r = await analyzeFile(file);
      setReport(r);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleSample(name) {
    setLoading(true);
    setError(null);
    setLastSource({ sampleName: name });
    try {
      const r = await analyzeSample(name);
      setReport(r);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleHtmlDownload(reportLang) {
    if (!lastSource) return;
    setError(null);
    try {
      const html = await fetchHtmlReport({
        file: lastSource.file,
        sampleName: lastSource.sampleName,
        lang: reportLang,
      });
      const base = safeDownloadName(report?.file?.name, "sample");
      downloadBlob(new Blob([html], { type: "text/html" }), `${base}.triage-report-${reportLang}.html`);
    } catch (e) {
      setError(e.message);
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-5xl px-4 py-8">
        <header className="mb-8 flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold">
              <span className="text-violet-400">IOCtopus</span>
            </h1>
            <p className="mt-1 max-w-xl text-sm text-slate-400">{t.tagline}</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setLang("en")}
              className={`rounded-lg px-3 py-1.5 text-sm font-medium ${lang === "en" ? "bg-violet-600 text-white" : "bg-slate-800 text-slate-300"}`}
            >
              EN
            </button>
            <button
              onClick={() => setLang("az")}
              className={`rounded-lg px-3 py-1.5 text-sm font-medium ${lang === "az" ? "bg-violet-600 text-white" : "bg-slate-800 text-slate-300"}`}
            >
              AZ
            </button>
          </div>
        </header>

        <UploadPanel t={t} onFile={handleFile} onSample={handleSample} samples={samples} loading={loading} />

        <p className="mt-3 text-xs text-slate-500">{t.offlineNote}</p>

        {error && (
          <div className="mt-4 rounded-lg border border-red-800 bg-red-950/40 p-3 text-sm text-red-300">{error}</div>
        )}

        {report && (
          <>
            <div className="my-6 flex flex-wrap gap-2">
              <button
                onClick={() => downloadJson(report, `${safeDownloadName(report.file.name, "sample")}.report.json`)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700"
              >
                {t.downloadJson}
              </button>
              <button
                onClick={() => downloadJson(buildStixBundle(report), `${safeDownloadName(report.file.name, "sample")}.stix.json`)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700"
              >
                {t.downloadStix}
              </button>
              <button
                onClick={() => handleHtmlDownload("en")}
                className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700"
              >
                {t.downloadHtmlEn}
              </button>
              <button
                onClick={() => handleHtmlDownload("az")}
                className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700"
              >
                {t.downloadHtmlAz}
              </button>
            </div>
            <ReportView report={report} t={t} />
          </>
        )}

        <footer className="mt-12 border-t border-slate-800 pt-6 text-xs text-slate-500">{t.footer}</footer>
      </div>
    </div>
  );
}
