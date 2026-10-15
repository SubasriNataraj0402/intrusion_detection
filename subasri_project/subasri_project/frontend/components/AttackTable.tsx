"use client";

import { useState } from "react";
import clsx from "clsx";
import { AttackRow, BlockedIPRow, blockIp, unblockIp } from "@/lib/api";
import AiAnalystModal from "./AiAnalystModal";


const SEVERITY_STYLE: Record<string, string> = {
  low: "bg-low/10 text-low",
  medium: "bg-medium/10 text-medium",
  high: "bg-high/10 text-high",
  critical: "bg-critical/10 text-critical",
};

interface AttackTableProps {
  attacks: AttackRow[];
  blockedIps?: BlockedIPRow[];
  onRefreshBlocked?: () => void;
}

export default function AttackTable({ attacks, blockedIps = [], onRefreshBlocked }: AttackTableProps) {
  const [selectedAttack, setSelectedAttack] = useState<AttackRow | null>(null);

  const blockedSet = new Set(blockedIps.map((b) => b.ip_address));

  const handleBlockIp = async (attack: AttackRow) => {
    try {
      await blockIp(
        attack.source_ip,
        `Manual block from Recent Detections table (${attack.attack_name})`,
        attack.attack_name
      );
      if (onRefreshBlocked) onRefreshBlocked();
    } catch (e) {
      console.error("Failed to block IP:", e);
    }
  };

  const handleUnblockIp = async (ip: string) => {
    try {
      await unblockIp(ip);
      if (onRefreshBlocked) onRefreshBlocked();
    } catch (e) {
      console.error("Failed to unblock IP:", e);
    }
  };

  return (
    <>
      <div className="rounded-xl border border-border bg-panel p-4">
        <div className="mb-3 flex items-center justify-between">
          <p className="text-sm font-medium text-slate-300">Recent Detections</p>
          <span className="text-xs text-indigo-400 font-medium flex items-center gap-1">
            ✨ Click any row to open Gemini AI Incident Analysis
          </span>
        </div>
        <div className="max-h-96 overflow-auto">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-panel text-slate-400">
              <tr>
                <th className="py-2 pr-3">Time</th>
                <th className="py-2 pr-3">Attack</th>
                <th className="py-2 pr-3">Source IP</th>
                <th className="py-2 pr-3">Destination IP</th>
                <th className="py-2 pr-3">Confidence</th>
                <th className="py-2 pr-3">Severity</th>
                <th className="py-2 pr-3">Risk</th>
                <th className="py-2 pr-3">Recommendation</th>
                <th className="py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {attacks.length === 0 && (
                <tr>
                  <td colSpan={9} className="py-6 text-center text-slate-500">
                    No attacks detected yet. Feed traffic via /api/predict or /api/upload-pcap, or enable live capture.
                  </td>
                </tr>
              )}
              {attacks.map((a) => {
                const isBlocked = blockedSet.has(a.source_ip);
                return (
                  <tr
                    key={a.attack_id}
                    onClick={() => setSelectedAttack(a)}
                    className="border-t border-border/60 hover:bg-slate-800/50 cursor-pointer transition"
                  >
                    <td className="py-2 pr-3 whitespace-nowrap text-slate-400">
                      {new Date(a.time).toLocaleTimeString()}
                    </td>
                    <td className="py-2 pr-3 font-medium text-slate-200">{a.attack_name}</td>
                    <td className="py-2 pr-3 font-mono text-slate-400 flex items-center gap-1">
                      {a.source_ip}
                      {isBlocked && (
                        <span className="rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 px-1 py-0.2 text-[10px] font-bold">
                          BLOCKED
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-3 font-mono text-slate-400">{a.destination_ip}</td>
                    <td className="py-2 pr-3">{(a.confidence * 100).toFixed(1)}%</td>
                    <td className="py-2 pr-3">
                      <span className={clsx("rounded px-2 py-0.5 font-medium", SEVERITY_STYLE[a.severity])}>
                        {a.severity}
                      </span>
                    </td>
                    <td className="py-2 pr-3">{a.risk_score}</td>
                    <td className="py-2 pr-3 text-slate-400 max-w-xs truncate">{a.recommendation}</td>
                    <td className="py-2 text-right">
                      <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                        {!isBlocked ? (
                          <button
                            onClick={() => handleBlockIp(a)}
                            className="rounded-lg bg-rose-600/20 hover:bg-rose-600/40 text-rose-300 border border-rose-500/30 px-2 py-1 text-[11px] font-medium transition flex items-center gap-1"
                            title="Block this IP address immediately"
                          >
                            🚫 Block IP
                          </button>
                        ) : (
                          <button
                            onClick={() => handleUnblockIp(a.source_ip)}
                            className="rounded-lg bg-emerald-600/20 hover:bg-emerald-600/40 text-emerald-300 border border-emerald-500/30 px-2 py-1 text-[11px] font-medium transition flex items-center gap-1"
                            title="Unblock this IP address"
                          >
                            🔓 Unblock IP
                          </button>
                        )}
                        <button
                          onClick={() => setSelectedAttack(a)}
                          className="rounded-lg bg-indigo-600/20 hover:bg-indigo-600/40 text-indigo-300 border border-indigo-500/30 px-2 py-1 text-[11px] font-medium transition flex items-center gap-1"
                        >
                          ✨ Ask Gemini
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>


      <AiAnalystModal
        attack={selectedAttack}
        onClose={() => setSelectedAttack(null)}
      />
    </>
  );
}

