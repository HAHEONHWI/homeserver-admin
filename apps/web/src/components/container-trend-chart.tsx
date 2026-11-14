"use client";

import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

type Sample = { time: string; cpu: number; memory: number };

export function ContainerTrendChart({ history }: { history: Sample[] }) {
  return <div className="container-trend__chart" role="img" aria-label={`최근 ${history.length}개 Live CPU 및 메모리 측정값`}>
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={history} margin={{ top: 8, right: 8, bottom: 0, left: -17 }}>
        <CartesianGrid stroke="var(--color-line)" strokeDasharray="3 3" />
        <XAxis dataKey="time" tick={{ fill: "var(--color-text-3)", fontSize: 9 }} minTickGap={30} />
        <YAxis tick={{ fill: "var(--color-text-3)", fontSize: 9 }} width={34} />
        <Tooltip contentStyle={{ background: "var(--color-surface-2)", border: "1px solid var(--color-line-2)", borderRadius: 7, fontSize: 10 }} formatter={(value, name) => [`${Number(value).toFixed(1)}%`, String(name).toLowerCase() === "cpu" ? "CPU" : "메모리"]} />
        <Line type="monotone" dataKey="cpu" name="CPU" stroke="var(--color-accent)" dot={false} strokeWidth={1.7} />
        <Line type="monotone" dataKey="memory" name="메모리" stroke="var(--color-violet)" dot={false} strokeWidth={1.7} />
      </LineChart>
    </ResponsiveContainer>
  </div>;
}
