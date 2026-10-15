export default function ChartPanel({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-border bg-panel p-4">
      <p className="mb-3 text-sm font-medium text-slate-300">{title}</p>
      <div className="h-64 w-full">{children}</div>
    </div>
  );
}
