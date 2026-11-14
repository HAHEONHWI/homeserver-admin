"use client";

import { useState } from "react";
import dynamic from "next/dynamic";
import { Activity, Cpu, HardDrive, MemoryStick, RefreshCw, Server, ShieldAlert, type LucideIcon } from "lucide-react";
import { useOverviewQuery } from "@/lib/queries";
import { ActionDialog } from "@/components/action-dialog";
import type { JobRequest } from "@/lib/contracts";

const OverviewChart = dynamic(
  () => import("@/components/overview-chart").then((module) => module.OverviewChart),
  { ssr: false, loading: () => <div className="chart-empty" role="status">차트 불러오는 중…</div> },
);
const number = new Intl.NumberFormat("ko-KR", { maximumFractionDigits: 1 });
const timeFormat = new Intl.DateTimeFormat("ko-KR", { hour: "2-digit", minute: "2-digit" });
const bytes = (value: number) => {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let n = value / 1024;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${number.format(n)} ${units[i]}`;
};
const duration = (seconds: number) => {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor(seconds % 86400 / 3600);
  const minutes = Math.floor(seconds % 3600 / 60);
  return `${days}일 ${hours}시간 ${minutes}분`;
};
const time = (value: string) => timeFormat.format(new Date(value));
const statusText: Record<string, string> = { healthy: "정상", warning: "주의", failed: "오류", stopped: "중지", not_configured: "미연결" };

function MetricCard({ label, value, unit, detail, percent, icon: Icon, warning = false }: { label: string; value: string; unit?: string; detail: string; percent?: number; icon: LucideIcon; warning?: boolean }) {
  return <section className={`metric-card ${warning ? "metric-card--warning" : ""}`} aria-label={label}>
    <div className="metric-card__head"><span>{label}</span><Icon className="metric-card__icon" size={15} aria-hidden="true" /></div>
    <div className="metric-card__value">{value}<span className="metric-card__unit">{unit}</span></div>
    {percent !== undefined && <div className="meter" role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(percent)}><div className="meter__fill" style={{ width: `${Math.min(percent, 100)}%` }} /></div>}
    <div className="metric-card__foot"><span>{detail}</span>{percent !== undefined && <span className="mono-text">{number.format(percent)}%</span>}</div>
  </section>;
}

function Status({ status }: { status: string }) {
  const className = status === "healthy" ? "healthy" : status === "warning" ? "warning" : status === "failed" ? "failed" : "";
  return <span className={`status-label ${className ? `status-label--${className}` : ""}`}><i className="status-label__dot" aria-hidden="true" />{statusText[status] ?? status}</span>;
}

function LoadingState() {
  return <div className="overview-grid" aria-label="서버 상태 불러오는 중" aria-busy="true">{Array.from({ length: 4 }, (_, i) => <div key={i} className="metric-card"><div className="skeleton" style={{ height: 12, width: "42%" }} /><div className="skeleton" style={{ height: 25, width: "65%", marginTop: 16 }} /><div className="skeleton" style={{ height: 4, marginTop: 13 }} /></div>)}<div className="panel panel--chart"><div className="skeleton" style={{ height: 16, width: 140 }} /><div className="skeleton" style={{ height: 185, marginTop: 17 }} /></div></div>;
}

export function OverviewPage() {
  const query = useOverviewQuery();
  const [action, setAction] = useState<{ operation: JobRequest["operation"]; target: string; label: string; id: string; enabled: boolean; reason: string } | null>(null);
  if (query.isPending) return <div className="page-content"><LoadingState /></div>;
  if (query.isError) return <div className="page-content"><div className="page-heading"><div><h1>개요</h1><p>서버 상태와 최근 운영 기록</p></div><button className="button" onClick={() => query.refetch()}><RefreshCw size={14} />다시 연결</button></div><section className="state-card" role="alert"><span className="state-card__icon"><ShieldAlert size={20} /></span><h2>API에 연결할 수 없습니다</h2><p>{query.error.message} · API 상태를 확인한 뒤 다시 시도하세요.</p></section></div>;

  const data = query.data;
  const mock = data.mode === "mock";
  const available = data.status === "connected";
  const cpuValue = available ? `${number.format(data.cpu.percent)}` : "—";
  const memoryValue = available ? `${number.format(data.memory.percent)}` : "—";
  const networkIn = data.network.receivedBytesPerSecond;
  const networkOut = data.network.sentBytesPerSecond;

  return <div className="page-content">
    <div className="page-heading">
      <div><h1>개요</h1><p>서버 상태와 최근 운영 기록 <span className="mono-text">· {time(data.updatedAt)} 갱신</span></p></div>
      <div className="heading-actions"><span className="status-pill"><i className="status-pill__dot" aria-hidden="true" />{mock ? "DEMO 모드" : available ? "Live 연결" : data.status === "unavailable" ? "에이전트 재연결 중" : "호스트 연결 대기"}</span><button className="button" onClick={() => query.refetch()} disabled={query.isFetching} aria-label="상태 새로고침"><RefreshCw size={14} className={query.isFetching ? "spin" : ""} /><span>새로고침</span></button></div>
    </div>
    {!available && <section className="state-banner" role="status"><Server size={14} /><span>호스트 에이전트가 연결되지 않아 Live 시스템 지표를 표시하지 않습니다.</span></section>}
    <div className="overview-grid">
      <MetricCard label="CPU 사용률" value={cpuValue} unit={available ? "%" : undefined} detail={available ? `논리 CPU ${data.cpu.cores.length}개 · Load ${data.cpu.loadAverage.map((v) => number.format(v)).join(" / ")}` : "호스트 에이전트 필요"} percent={available ? data.cpu.percent : undefined} icon={Cpu} warning={available && data.cpu.percent >= 85} />
      <MetricCard label="메모리" value={memoryValue} unit={available ? "%" : undefined} detail={available ? `${bytes(data.memory.usedBytes)} / ${bytes(data.memory.totalBytes)}` : "호스트 에이전트 필요"} percent={available ? data.memory.percent : undefined} icon={MemoryStick} warning={available && data.memory.percent >= 90} />
      <MetricCard label="스토리지" value={available && data.storage.length ? `${number.format(data.storage[0].percent)}` : "—"} unit={available && data.storage.length ? "%" : undefined} detail={available && data.storage.length ? `${data.storage.length}개 mount · ${data.storage[0].mount}` : available ? "확인된 스토리지 경로 미구성" : "호스트 에이전트 필요"} percent={available && data.storage.length ? data.storage[0].percent : undefined} icon={HardDrive} warning={available && Boolean(data.storage[0] && data.storage[0].percent >= 85)} />
      <MetricCard label="네트워크" value={available ? bytes(networkIn) : "—"} unit={available ? "/s ↓" : undefined} detail={available ? `${bytes(networkOut)} /s ↑ 송신` : "호스트 에이전트 필요"} icon={Activity} />

      <section className="panel panel--chart">
        <div className="panel__head"><div><h2 className="panel__title">자원 사용 추이</h2><p className="panel__subtitle">최근 측정 기록</p></div><div className="legend"><span><i />CPU</span><span><i />메모리</span></div></div>
        {available && data.history.length ? <OverviewChart history={data.history} /> : <div className="chart-empty">{available ? "아직 측정 기록이 없습니다." : "호스트 에이전트 연결 후 표시됩니다."}</div>}
      </section>

      <section className="panel panel--server">
        <div className="panel__head"><div><h2 className="panel__title">서버 정보</h2><p className="panel__subtitle">시스템 연결 요약</p></div><Server size={15} className="metric-card__icon" /></div>
        <div className="server-head"><div className="server-head__icon"><Server size={18} /></div><div><div className="server-head__name">{data.serverName}</div><div className="server-head__sub">{mock ? "SIMULATED ENVIRONMENT" : available ? "LIVE SYSTEM" : "AGENT NOT CONNECTED"}</div></div></div>
        <div className="server-rows">
          <div className="server-row"><span>가동 시간</span><strong>{available ? duration(data.uptimeSeconds) : "—"}</strong></div>
          <div className="server-row"><span>스왑</span><strong>{available ? `${bytes(data.swap.usedBytes)} / ${bytes(data.swap.totalBytes)}` : "—"}</strong></div>
          <div className="server-row"><span>컨테이너</span><strong>{data.docker.status === "connected" ? `${data.docker.running} / ${data.docker.total} 실행 중` : data.docker.message}</strong></div>
        </div>
        {available && data.storage.length > 0 && <div className="section-break"><div className="panel__head"><h3 className="panel__title">스토리지</h3><span className="muted-copy" style={{ fontSize: 9 }}>용량 사용</span></div>{data.storage.slice(0, 2).map((disk) => <div className="storage-item" key={`${disk.name}:${disk.mount}`}><div className="storage-item__head"><span>{disk.name} <span className="muted-copy">{disk.mount}</span></span><span>{number.format(disk.percent)}%</span></div><div className="meter"><div className="meter__fill" style={{ width: `${disk.percent}%` }} /></div><div className="storage-item__meta"><span>{bytes(disk.usedBytes)} 사용</span><span>{bytes(disk.totalBytes)} 전체</span></div></div>)}</div>}
        {!available && <div className="section-break"><button className="button button--small" onClick={() => setAction({ id: "reboot", label: "서버 재부팅", operation: "reboot", target: data.serverName, enabled: false, reason: "호스트 에이전트 미연결" })} disabled aria-label="서버 재부팅 차단됨"><RefreshCw size={12} />서버 작업 차단됨</button></div>}
      </section>

      <section className="panel panel--services">
        <div className="panel__head"><div><h2 className="panel__title">서비스 상태</h2><p className="panel__subtitle">{data.services.length}개 확인 항목</p></div></div>
        <table className="service-table"><thead><tr><th>서비스</th><th>상태</th><th>마지막 확인</th><th>설명</th></tr></thead><tbody>{data.services.map((service) => <tr key={service.name}><td><span className="service-name"><i className="service-name__icon"><Server size={12} /></i>{service.name}</span></td><td><Status status={service.status} /></td><td className="mono-text">{time(service.checkedAt)}</td><td className="muted-copy">{service.detail}</td></tr>)}</tbody></table>
      </section>

      <section className="panel panel--activity">
        <div className="panel__head"><div><h2 className="panel__title">최근 활동</h2><p className="panel__subtitle">배포, 알림 및 관리 기록</p></div></div>
        {data.activity.length ? <div className="activity-list">{data.activity.slice(0, 5).map((event) => <div className="activity-item" key={event.id}><span className="activity-item__icon"><Activity size={13} /></span><div><div className="activity-item__title">{event.title}</div><div className="activity-item__detail">{event.detail}</div></div><time className="activity-item__time">{time(event.createdAt)}</time></div>)}</div> : <div className="empty-inline">기록된 활동이 없습니다.</div>}
      </section>
    </div>
    {action && <ActionDialog action={action} mode={data.mode} onClose={() => setAction(null)} />}
  </div>;
}
