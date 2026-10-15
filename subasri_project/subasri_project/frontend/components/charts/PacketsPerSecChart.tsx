"use client";

import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

export default function PacketsPerSecChart({ data }: { data: { time: string; packets: number }[] }) {
  const formatted = data.map((d) => ({
    ...d,
    label: new Date(d.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  }));

  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={formatted}>
        <CartesianGrid stroke="#1f2b3a" strokeDasharray="3 3" />
        <XAxis dataKey="label" stroke="#64748b" fontSize={11} />
        <YAxis stroke="#64748b" fontSize={11} />
        <Tooltip contentStyle={{ background: "#111823", border: "1px solid #1f2b3a", fontSize: 12 }} />
        <Line type="monotone" dataKey="packets" stroke="#38bdf8" strokeWidth={2} dot={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}
