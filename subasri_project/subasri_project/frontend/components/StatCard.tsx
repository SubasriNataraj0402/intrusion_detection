export default function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: string | number;
  accent?: "accent" | "critical" | "high" | "low";
}) {
  const colorClass =
    accent === "critical"
      ? "text-critical"
      : accent === "high"
      ? "text-high"
      : accent === "low"
      ? "text-low"
      : "text-accent";

  return (
    <div className="rounded-xl border border-border bg-panel p-4">
      <p className="text-xs uppercase tracking-wide text-slate-400">{label}</p>
      <p className={`mt-2 text-2xl font-semibold ${colorClass}`}>{value}</p>
    </div>
  );
}
