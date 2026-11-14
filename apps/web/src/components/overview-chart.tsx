"use client";

import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Overview } from "@/lib/contracts";

const number = new Intl.NumberFormat("ko-KR", { maximumFractionDigits: 1 });

export function OverviewChart({ history }: { history: Overview["history"] }) {
  return <div className="chart" role="img" aria-label={`최근 CPU 및 메모리 추이, ${history.length}개 측정값`}>
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={history} margin={{ top: 8, right: 4, bottom: 0, left: -20 }}>
        <defs>
          <linearGradient id="cpuFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--color-accent)" stopOpacity={.24} /><stop offset="95%" stopColor="var(--color-accent)" stopOpacity={0} /></linearGradient>
          <linearGradient id="memoryFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--color-violet)" stopOpacity={.2} /><stop offset="95%" stopColor="var(--color-violet)" stopOpacity={0} /></linearGradient>
        </defs>
        <CartesianGrid stroke="var(--color-line)" strokeDasharray="3 4" vertical={false} />
        <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: "var(--color-text-3)", fontSize: 9 }} minTickGap={20} />
        <YAxis domain={[0, 100]} axisLine={false} tickLine={false} tick={{ fill: "var(--color-text-3)", fontSize: 9 }} tickFormatter={(value: number) => `${value}%`} />
        <Tooltip content={({ active, payload, label }) => active && payload?.length ? <div className="chart-tooltip"><p>{label}</p>{payload.map((entry) => <p key={String(entry.dataKey)} style={{ color: String(entry.color) }}>{String(entry.name)} {number.format(Number(entry.value))}%</p>)}</div> : null} />
        <Area type="monotone" dataKey="cpu" name="CPU" stroke="var(--color-accent)" strokeWidth={1.7} fill="url(#cpuFill)" isAnimationActive={false} />
        <Area type="monotone" dataKey="memory" name="메모리" stroke="var(--color-violet)" strokeWidth={1.7} fill="url(#memoryFill)" isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  </div>;
}
