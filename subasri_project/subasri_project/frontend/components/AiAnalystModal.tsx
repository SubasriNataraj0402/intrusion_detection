"use client";

import { useState, useEffect } from "react";
import { AttackRow, API_URL } from "@/lib/api";

interface AiReport {
  executive_summary?: string;
  threat_vector?: string;
  firewall_commands?: string[];
  remediation_steps?: string[];
  confidence_assessment?: string;
  ai_provider?: string;
}

export default function AiAnalystModal({
  attack,
  onClose,
}: {
  attack: AttackRow | null;
  onClose: () => void;
}) {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<AiReport | null>(null);
  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState<{ role: "user" | "ai"; text: string }[]>([]);
  const [chatLoading, setChatLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  useEffect(() => {
    if (!attack) return;
    setLoading(true);
    setReport(null);
    setChatMessages([]);

    fetch(`${API_URL}/ai/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        attack_id: attack.attack_id,
        attack_name: attack.attack_name,
        confidence: attack.confidence,
        severity: attack.severity,
        risk_score: attack.risk_score,
        source_ip: attack.source_ip,
        destination_ip: attack.destination_ip,
        explanation: attack.explanation ? (typeof attack.explanation === "string" ? JSON.parse(attack.explanation) : attack.explanation) : {},
      }),
    })
      .then((res) => res.json())
      .then((data) => {
        setReport(data);
      })
      .catch((err) => console.error("Failed to fetch AI report:", err))
      .finally(() => setLoading(false));
  }, [attack]);

  const handleSendChat = async () => {
    if (!chatInput.trim()) return;
    const msg = chatInput;
    setChatInput("");
    setChatMessages((prev) => [...prev, { role: "user", text: msg }]);
    setChatLoading(true);

    try {
      const res = await fetch(`${API_URL}/ai/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: msg,
          context: { attack, report },
        }),
      });
      const data = await res.json();
      setChatMessages((prev) => [...prev, { role: "ai", text: data.reply }]);
    } catch (err) {
      setChatMessages((prev) => [
        ...prev,
        { role: "ai", text: "Failed to connect to AI Analyst service." },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  const copyCommand = (cmd: string, idx: number) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  if (!attack) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="relative w-full max-w-3xl rounded-2xl border border-indigo-500/30 bg-slate-900 p-6 text-slate-100 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-tr from-indigo-600 to-purple-600 font-bold text-white shadow-lg">
              ✨
            </div>
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                Gemini Pro AI Incident Analysis
                <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  {report?.ai_provider || "AI Engine"}
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Threat: <span className="font-mono text-amber-400 font-semibold">{attack.attack_name}</span> | Target: {attack.destination_ip}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white transition"
          >
            ✕
          </button>
        </div>

        {loading ? (
          <div className="flex flex-col items-center justify-center py-12 gap-3 text-indigo-400">
            <div className="h-8 w-8 animate-spin rounded-full border-4 border-indigo-500 border-t-transparent"></div>
            <p className="text-sm font-medium animate-pulse">Generating Gemini Pro Threat Intelligence & Mitigation Plan...</p>
          </div>
        ) : (
          <div className="space-y-5 max-h-[70vh] overflow-y-auto pr-2">
            {/* Executive Summary */}
            <div className="rounded-xl border border-indigo-500/20 bg-indigo-950/20 p-4">
              <h3 className="text-xs uppercase tracking-wider font-semibold text-indigo-400 mb-1">Executive Summary</h3>
              <p className="text-sm text-slate-200 leading-relaxed">{report?.executive_summary}</p>
            </div>

            {/* Threat Vector */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
              <h3 className="text-xs uppercase tracking-wider font-semibold text-purple-400 mb-1">Technical Threat Vector</h3>
              <p className="text-xs text-slate-300 leading-relaxed">{report?.threat_vector}</p>
            </div>

            {/* Firewall Commands */}
            {report?.firewall_commands && report.firewall_commands.length > 0 && (
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                <h3 className="text-xs uppercase tracking-wider font-semibold text-emerald-400 mb-2">Instant Mitigation Firewall Commands</h3>
                <div className="space-y-2">
                  {report.firewall_commands.map((cmd, idx) => (
                    <div key={idx} className="flex items-center justify-between rounded-lg bg-slate-900 border border-slate-800 p-2 text-xs font-mono text-emerald-300">
                      <code>{cmd}</code>
                      <button
                        onClick={() => copyCommand(cmd, idx)}
                        className="ml-2 rounded px-2 py-1 text-[10px] font-sans font-semibold bg-emerald-950 hover:bg-emerald-900 text-emerald-300 transition"
                      >
                        {copiedIndex === idx ? "Copied! ✓" : "Copy"}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Remediation Steps */}
            {report?.remediation_steps && (
              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                <h3 className="text-xs uppercase tracking-wider font-semibold text-cyan-400 mb-2">SOC Remediation Playbook</h3>
                <ul className="list-disc list-inside text-xs text-slate-300 space-y-1">
                  {report.remediation_steps.map((step, idx) => (
                    <li key={idx}>{step}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Interactive Chat */}
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 space-y-3">
              <h3 className="text-xs uppercase tracking-wider font-semibold text-slate-300 flex items-center gap-1.5">
                💬 Ask Gemini AI Analyst
              </h3>
              {chatMessages.length > 0 && (
                <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                  {chatMessages.map((m, idx) => (
                    <div
                      key={idx}
                      className={`text-xs p-2.5 rounded-xl max-w-[85%] ${
                        m.role === "user"
                          ? "ml-auto bg-indigo-600 text-white"
                          : "bg-slate-800 text-slate-200 border border-slate-700"
                      }`}
                    >
                      {m.text}
                    </div>
                  ))}
                  {chatLoading && (
                    <div className="text-xs text-indigo-400 animate-pulse">Gemini Analyst is typing...</div>
                  )}
                </div>
              )}
              <div className="flex gap-2">
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSendChat()}
                  placeholder="Ask Gemini how to investigate or mitigate this incident..."
                  className="flex-1 rounded-xl bg-slate-900 border border-slate-700 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                />
                <button
                  onClick={handleSendChat}
                  disabled={chatLoading}
                  className="rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 px-4 py-2 text-xs font-semibold text-white hover:opacity-90 transition disabled:opacity-50"
                >
                  Send
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
