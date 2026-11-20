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

export default function ReportView({ report, t }) {
  const { file, pe, yara, iocs, attack, score } = report;

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
        {iocs.az_related.length > 0 && (
          <div className="mt-4 rounded-lg border border-amber-800 bg-amber-950/40 p-3 text-sm text-amber-300">{t.azNote}</div>
        )}
      </Section>

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
