import clsx from "clsx";
import { AlertRow, api } from "@/lib/api";

const SEVERITY_DOT: Record<string, string> = {
  low: "bg-low",
  medium: "bg-medium",
  high: "bg-high",
  critical: "bg-critical",
};

export default function AlertPanel({
  alerts,
  onAcknowledged,
}: {
  alerts: AlertRow[];
  onAcknowledged: (id: string) => void;
}) {
  async function acknowledge(id: string) {
    try {
      await api.post(`/alerts/${id}/acknowledge`);
      onAcknowledged(id);
    } catch {
      // no-op; row stays as-is if the request fails
    }
  }

  return (
    <div className="rounded-xl border border-border bg-panel p-4">
      <p className="mb-3 text-sm font-medium text-slate-300">Live Alerts</p>
      <div className="max-h-96 space-y-2 overflow-auto">
        {alerts.length === 0 && <p className="text-xs text-slate-500">No alerts raised yet.</p>}
        {alerts.map((a) => (
          <div
            key={a.alert_id}
            className={clsx(
              "flex items-start justify-between gap-2 rounded-lg border border-border/60 p-3 text-xs",
              a.acknowledged && "opacity-50"
            )}
          >
            <div className="flex items-start gap-2">
              <span className={clsx("mt-1 h-2 w-2 shrink-0 rounded-full", SEVERITY_DOT[a.severity])} />
              <div>
                <p className="text-slate-200">{a.message}</p>
                <p className="mt-1 text-slate-500">{new Date(a.created_time).toLocaleString()}</p>
              </div>
            </div>
            {!a.acknowledged && (
              <button
                onClick={() => acknowledge(a.alert_id)}
                className="shrink-0 rounded border border-border px-2 py-1 text-[11px] text-slate-300 hover:border-accent hover:text-accent"
              >
                Ack
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
