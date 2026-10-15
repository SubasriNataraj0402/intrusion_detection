"use client";

import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

export default function AttackTypesChart({ data }: { data: { attack_name: string; count: number }[] }) {
  if (!data.length) {
    return <p className="flex h-full items-center justify-center text-sm text-slate-500">No attacks detected yet</p>;
  }
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={data} layout="vertical" margin={{ left: 20 }}>
        <CartesianGrid stroke="#1f2b3a" strokeDasharray="3 3" />
        <XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} />
        <YAxis type="category" dataKey="attack_name" stroke="#64748b" fontSize={11} width={90} />
        <Tooltip
          cursor={{ fill: "#ffffff", opacity: 0.04 }}
          contentStyle={{ background: "#111823", border: "1px solid #1f2b3a", fontSize: 12 }}
        />
        <Bar dataKey="count" fill="#f97316" radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
