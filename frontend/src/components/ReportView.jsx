import ScoreBadge from "./ScoreBadge";

function Section({ title, children }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">{title}</h3>
      {children}
    </div>
  );
}

function Pill({ children, tone = "slate" }) {
  const tones = {
    slate: "bg-slate-800 text-slate-200",
    red: "bg-red-950 text-red-400",
    amber: "bg-amber-950 text-amber-400",
    violet: "bg-violet-950 text-violet-300",
  };
  return <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium ${tones[tone]}`}>{children}</span>;
}

const SEVERITY_TONE = { high: "red", medium: "amber", low: "slate", info: "violet" };

function KV({ label, children }) {
  return (
    <div className="flex justify-between gap-4 border-t border-slate-800 py-1.5 first:border-t-0">
      <dt className="text-slate-500">{label}</dt>
      <dd className="min-w-0 text-right text-slate-200">{children}</dd>
    </div>
  );
}

function Flag({ on, label }) {
  return <span className={on ? "text-emerald-400" : "text-red-400"}>{label} {on ? "✓" : "✗"}</span>;
}

function PeHeader({ headers, t }) {
  if (!headers) return <p className="text-slate-500">{t.noFindings}</p>;
  return (
    <dl className="text-sm">
      <KV label={t.machine}>{headers.machine}</KV>
      <KV label={t.fileType}>{headers.file_type}</KV>
      <KV label={t.compileTime}>
        {headers.compile_time ? headers.compile_time.replace("T", " ").replace("+00:00", " UTC") : <span className="text-red-400">{t.stripped}</span>}
      </KV>
      <KV label={t.entryPoint}><span className="font-mono">{headers.entry_point}</span></KV>
      <KV label={t.imageBase}><span className="font-mono">{headers.image_base}</span></KV>
      <KV label={t.subsystem}>{headers.subsystem}</KV>
      <KV label={t.linker}>{headers.linker_version}</KV>
      <KV label={t.protections}>
        <span className="inline-flex flex-wrap justify-end gap-x-2">
          <Flag on={headers.aslr} label="ASLR" />
          <Flag on={headers.dep} label="DEP" />
          <Flag on={headers.cfg} label="CFG" />
        </span>
      </KV>
      <KV label={t.signature}>
        <span title={t.signatureNote}>{headers.embedded_signature ? t.present : t.absent}</span>
      </KV>
      {!headers.embedded_signature && <p className="pt-1 text-xs text-slate-500">{t.signatureNote}</p>}
    </dl>
  );
}

function Imports({ imports, suspicious, t }) {
  const dlls = Object.entries(imports || {});
  const total = dlls.reduce((n, [, funcs]) => n + funcs.length, 0);
  const flagged = new Set((suspicious || []).map((s) => s.api));
  return (
    <div className="space-y-3 text-sm">
      <p className="text-slate-400">{t.importsSummary(total, dlls.length)}</p>
      {suspicious?.length > 0 && (
        <div>
          <p className="mb-1.5 text-slate-500">{t.notableApis}</p>
          <ul className="space-y-1">
            {suspicious.map((s, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2">
                <Pill tone="red">{s.category}</Pill>
                <span className="font-mono text-red-400">{s.api}</span>
                <span className="font-mono text-xs text-slate-500">{s.dll}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {dlls.length > 0 && (
        <details className="rounded-lg border border-slate-800 p-2">
          <summary className="cursor-pointer text-slate-400">{t.showAll}</summary>
          <div className="mt-2 max-h-80 space-y-2 overflow-y-auto pr-1">
            {dlls.map(([dll, funcs]) => (
              <div key={dll}>
                <p className="font-mono text-xs text-slate-300">
                  {dll} <span className="text-slate-600">({funcs.length})</span>
                </p>
                <p className="break-words font-mono text-xs leading-relaxed text-slate-500">
                  {funcs.map((f, i) => (
                    <span key={i} className={flagged.has(f) ? "font-semibold text-red-400" : ""}>
                      {f}
                      {i < funcs.length - 1 ? ", " : ""}
                    </span>
                  ))}
                </p>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

const STRING_CATEGORIES = [
  ["autorun_registry", "autorun", "red"],
  ["registry", "registry", "slate"],
  ["mutexes", "mutexes", "amber"],
  ["paths", "paths", "slate"],
  ["commands", "commands", "red"],
  ["user_agents", "userAgents", "amber"],
];

function InterestingStrings({ strings, t }) {
  if (!strings) return null;
  const groups = STRING_CATEGORIES.filter(([key]) => strings.interesting?.[key]?.length);
  return (
    <div className="space-y-4 text-sm">
      <p className="text-slate-400">{t.stringsSummary(strings.total, strings.ascii, strings.wide)}</p>
      {groups.length === 0 ? (
        <p className="text-slate-500">{t.noFindings}</p>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {groups.map(([key, labelKey, tone]) => (
            <div key={key} className="min-w-0">
              <p className="mb-1.5 flex items-center gap-2 text-slate-500">
                {t[labelKey]} <Pill tone={tone}>{strings.interesting[key].length}</Pill>
              </p>
              <ul className="max-h-48 space-y-1 overflow-y-auto">
                {strings.interesting[key].map((s, i) => (
                  <li key={i} className={`break-all font-mono text-xs ${tone === "red" ? "text-red-400" : "text-slate-300"}`}>
                    {s}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ReportView({ report, t }) {
  const { file, pe, yara, iocs, attack, score, strings } = report;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">
            {t.file}: <span className="font-mono text-slate-200">{file.name}</span> &middot; {t.size}: {file.size.toLocaleString()} B
          </p>
          <p className="mt-1 font-mono text-xs text-slate-500">SHA256 {file.sha256}</p>
        </div>
        <ScoreBadge score={score} t={t} />
      </div>

      <Section title={t.reasons}>
        {score.reasons.length === 0 ? (
          <p className="text-slate-500">{t.noFindings}</p>
        ) : (
          <ul className="space-y-1.5 text-sm">
            {score.reasons.map((r, i) => (
              <li key={i} className="font-mono text-slate-300">
                {r}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <div className="grid gap-4 md:grid-cols-2">
        <Section title={t.attack}>
          {attack.length === 0 ? (
            <p className="text-slate-500">{t.noFindings}</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {attack.map((a, i) => (
                <li key={i} className="flex items-start gap-2">
                  <Pill tone="violet">{a.technique}</Pill>
                  <span className="text-slate-300">
                    {a.name} - <span className="text-slate-500">{a.reason}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title={t.yara}>
          {yara.length === 0 ? (
            <p className="text-slate-500">{t.noFindings}</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {yara.map((y, i) => (
                <li key={i} className="flex items-start gap-2">
                  <Pill tone={SEVERITY_TONE[y.severity] || "slate"}>{y.severity}</Pill>
                  <span className="text-slate-300">
                    <span className="font-mono">{y.rule}</span>
                    {y.description && <span className="text-slate-500"> - {y.description}</span>}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>

      <Section title={t.iocs}>
        <div className="grid gap-3 text-sm md:grid-cols-2">
          <div>
            <p className="mb-1 text-slate-500">{t.urls}</p>
            {iocs.urls.length ? iocs.urls.map((u, i) => <p key={i} className="font-mono text-red-400">{u}</p>) : <p className="text-slate-600">-</p>}
          </div>
          <div>
            <p className="mb-1 text-slate-500">{t.domains}</p>
            {iocs.domains.length ? iocs.domains.map((d, i) => <p key={i} className="font-mono text-red-400">{d}</p>) : <p className="text-slate-600">-</p>}
          </div>
          <div>
            <p className="mb-1 text-slate-500">{t.ips}</p>
            {iocs.ips.length ? iocs.ips.map((ip, i) => <p key={i} className="font-mono text-red-400">{ip}</p>) : <p className="text-slate-600">-</p>}
          </div>
          <div>
            <p className="mb-1 text-slate-500">{t.privateIps}</p>
            {iocs.private_ips.length ? iocs.private_ips.map((ip, i) => <p key={i} className="font-mono text-slate-400">{ip}</p>) : <p className="text-slate-600">-</p>}
          </div>
        </div>
        {(iocs.registry_keys?.length > 0 || iocs.mutexes?.length > 0) && (
          <div className="mt-3 grid gap-3 border-t border-slate-800 pt-3 text-sm md:grid-cols-2">
            <div className="min-w-0">
              <p className="mb-1 text-slate-500">{t.registry}</p>
              {iocs.registry_keys?.length ? iocs.registry_keys.map((k, i) => <p key={i} className="break-all font-mono text-amber-400">{k}</p>) : <p className="text-slate-600">-</p>}
            </div>
            <div className="min-w-0">
              <p className="mb-1 text-slate-500">{t.mutexes}</p>
              {iocs.mutexes?.length ? iocs.mutexes.map((m, i) => <p key={i} className="break-all font-mono text-amber-400">{m}</p>) : <p className="text-slate-600">-</p>}
            </div>
          </div>
        )}
        {iocs.az_related.length > 0 && (
          <div className="mt-4 rounded-lg border border-amber-800 bg-amber-950/40 p-3 text-sm text-amber-300">{t.azNote}</div>
        )}
      </Section>

      <Section title={t.interestingStrings}>
        <InterestingStrings strings={strings} t={t} />
      </Section>

      <div className="grid gap-4 md:grid-cols-2">
        <Section title={t.peHeader}>
          <PeHeader headers={pe.headers} t={t} />
        </Section>
        <Section title={t.imports}>
          <Imports imports={pe.imports} suspicious={pe.suspicious_imports} t={t} />
        </Section>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Section title={t.sections}>
          <table className="w-full text-left text-sm">
            <thead className="text-slate-500">
              <tr>
                <th className="pb-2">Name</th>
                <th className="pb-2">Raw</th>
                <th className="pb-2">Virtual</th>
                <th className="pb-2">Entropy</th>
              </tr>
            </thead>
            <tbody>
              {pe.sections.map((s, i) => (
                <tr key={i} className="border-t border-slate-800 text-slate-300">
                  <td className="py-1.5 font-mono">{s.name}</td>
                  <td className="py-1.5">{s.raw_size}</td>
                  <td className="py-1.5">{s.virtual_size}</td>
                  <td className={`py-1.5 ${s.entropy > 7.2 ? "font-semibold text-amber-400" : ""}`}>{s.entropy}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>

        <Section title={t.anomalies}>
          {pe.anomalies.length === 0 ? (
            <p className="text-slate-500">{t.noFindings}</p>
          ) : (
            <ul className="space-y-1.5 text-sm text-slate-300">
              {pe.anomalies.map((a, i) => (
                <li key={i}>
                  <Pill>{a.type}</Pill> <span className="text-slate-400">{a.detail}</span>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>
    </div>
  );
}
