const VERDICT_STYLES = {
  Clean: "bg-emerald-950 text-emerald-400 border-emerald-700",
  Suspicious: "bg-amber-950 text-amber-400 border-amber-700",
  "Likely Malicious": "bg-orange-950 text-orange-400 border-orange-700",
  Malicious: "bg-red-950 text-red-400 border-red-700",
};

export default function ScoreBadge({ score, t }) {
  const style = VERDICT_STYLES[score.verdict] || VERDICT_STYLES.Suspicious;
  const label = t?.verdicts?.[score.verdict] || score.verdict;
  return (
    <div className={`inline-flex items-center gap-3 rounded-xl border px-5 py-3 ${style}`}>
      <span className="text-3xl font-bold tabular-nums">{score.value}</span>
      <span className="text-sm opacity-70">/100</span>
      <span className="ml-2 text-lg font-semibold">{label}</span>
    </div>
  );
}
