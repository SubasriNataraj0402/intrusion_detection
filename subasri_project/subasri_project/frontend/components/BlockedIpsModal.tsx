"use client";

import { BlockedIPRow, unblockIp } from "@/lib/api";

interface Props {
  blockedIps: BlockedIPRow[];
  isOpen: boolean;
  onClose: () => void;
  onRefresh: () => void;
}

export default function BlockedIpsModal({ blockedIps, isOpen, onClose, onRefresh }: Props) {
  if (!isOpen) return null;

  const handleUnblock = async (ip: string) => {
    try {
      await unblockIp(ip);
      onRefresh();
    } catch (e) {
      console.error("Failed to unblock IP:", e);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="w-full max-w-3xl rounded-xl border border-border bg-panel p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-200">
        <div className="flex items-center justify-between border-b border-border pb-4 mb-4">
          <div className="flex items-center gap-2">
            <span className="text-xl">🛡️</span>
            <div>
              <h2 className="text-lg font-semibold text-slate-100">Active Protection — Blocked IPs</h2>
              <p className="text-xs text-slate-400">Threat Prevention & Firewall Drop List</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 font-bold px-2 py-1 text-sm rounded-lg hover:bg-slate-800 transition"
          >
            ✕
          </button>
        </div>

        <div className="max-h-96 overflow-y-auto">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-panel text-slate-400 border-b border-border">
              <tr>
                <th className="py-2 pr-3">Blocked IP</th>
                <th className="py-2 pr-3">Attack Type</th>
                <th className="py-2 pr-3">Reason</th>
                <th className="py-2 pr-3">Blocked By</th>
                <th className="py-2 pr-3">Date/Time</th>
                <th className="py-2 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {blockedIps.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No IPs currently blocked. High severity attacks will be auto-blocked or you can manually block an IP from Recent Detections.
                  </td>
                </tr>
              ) : (
                blockedIps.map((b) => (
                  <tr key={b.id} className="border-t border-border/40 hover:bg-slate-800/40">
                    <td className="py-3 pr-3 font-mono font-medium text-rose-400 flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse" />
                      {b.ip_address}
                    </td>
                    <td className="py-3 pr-3 font-medium text-slate-300 capitalize">{b.attack_type}</td>
                    <td className="py-3 pr-3 text-slate-400 max-w-xs truncate">{b.reason}</td>
                    <td className="py-3 pr-3 text-slate-400">{b.blocked_by}</td>
                    <td className="py-3 pr-3 text-slate-400 whitespace-nowrap">
                      {new Date(b.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 text-right">
                      <button
                        onClick={() => handleUnblock(b.ip_address)}
                        className="rounded-md bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-2.5 py-1 font-medium transition"
                      >
                        🔓 Unblock
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="mt-5 pt-3 border-t border-border flex items-center justify-between text-xs text-slate-400">
          <span>Active rules: <strong className="text-slate-200">{blockedIps.length}</strong></span>
          <button
            onClick={onClose}
            className="rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-1.5 font-medium transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
