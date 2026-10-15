"use client";

import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  low: "#22c55e",
  medium: "#eab308",
  high: "#f97316",
  critical: "#ef4444",
};

export default function SeverityChart({ data }: { data: { severity: string; count: number }[] }) {
  if (!data.length) {
    return <p className="flex h-full items-center justify-center text-sm text-slate-500">No attacks detected yet</p>;
  }
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={data}>
        <CartesianGrid stroke="#1f2b3a" strokeDasharray="3 3" />
        <XAxis dataKey="severity" stroke="#64748b" fontSize={11} />
        <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
        <Tooltip
          cursor={{ fill: "#ffffff", opacity: 0.04 }}
          contentStyle={{ background: "#111823", border: "1px solid #1f2b3a", fontSize: 12 }}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {data.map((d, i) => (
            <Cell key={i} fill={SEVERITY_COLORS[d.severity] || "#64748b"} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
