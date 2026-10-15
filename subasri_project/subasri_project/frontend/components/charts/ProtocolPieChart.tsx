"use client";

import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";

const COLORS = ["#38bdf8", "#22c55e", "#eab308", "#f97316", "#a78bfa", "#ef4444"];

export default function ProtocolPieChart({ data }: { data: { protocol: string; count: number }[] }) {
  if (!data.length) {
    return <p className="flex h-full items-center justify-center text-sm text-slate-500">No data yet</p>;
  }
  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie data={data} dataKey="count" nameKey="protocol" innerRadius={50} outerRadius={80} paddingAngle={2}>
          {data.map((_, i) => (
            <Cell key={i} fill={COLORS[i % COLORS.length]} />
          ))}
        </Pie>
        <Tooltip contentStyle={{ background: "#111823", border: "1px solid #1f2b3a", fontSize: 12 }} />
        <Legend wrapperStyle={{ fontSize: 12 }} />
      </PieChart>
    </ResponsiveContainer>
  );
}
