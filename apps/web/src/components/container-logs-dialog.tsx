"use client";

import { useEffect, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { LoaderCircle, Pause, Play, RefreshCw, ScrollText, X } from "lucide-react";
import { useContainerLogsQuery, useContainerStatsQuery } from "@/lib/queries";

const ContainerTrendChart = dynamic(
  () => import("@/components/container-trend-chart").then((module) => module.ContainerTrendChart),
  { ssr: false, loading: () => <div className="container-trend__chart" role="status">차트 불러오는 중…</div> },
);
type Tab = "overview" | "logs";

function formatBytes(value: number | null | undefined) {
  if (value == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1; }
  return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function ContainerLogsDialog({
  container,
  mode,
  initialTab,
  onClose,
}: {
  container: { id: string; name: string; status: string; detail: string };
  mode: "mock" | "live";
  initialTab: Tab;
  onClose: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const [tab, setTab] = useState<Tab>(initialTab);
  const [paused, setPaused] = useState(false);
  const [level, setLevel] = useState("all");
  const [history, setHistory] = useState<{ time: string; cpu: number; memory: number }[]>([]);
  const logs = useContainerLogsQuery(container.id, tab === "logs", paused);
  const stats = useContainerStatsQuery(container.id, tab === "overview");
  const lastSample = useRef("");

  useEffect(() => {
    const sample = stats.data;
    const cpu = sample?.cpuPercent;
    const memory = sample?.memoryPercent;
    if (!sample || sample.mode !== "live" || sample.status !== "connected" || cpu == null || memory == null || sample.updatedAt === lastSample.current) return;
    lastSample.current = sample.updatedAt;
    setHistory((current) => [...current, {
      time: new Date(sample.updatedAt).toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      cpu,
      memory,
    }].slice(-24));
  }, [stats.data]);

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      if (event.key !== "Tab") return;
      const drawer = document.querySelector<HTMLElement>("[data-container-detail-drawer]");
      const focusable = drawer?.querySelectorAll<HTMLElement>('button:not(:disabled), [href], input:not(:disabled), select:not(:disabled)');
      if (!focusable?.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      previousFocus?.focus();
    };
  }, [onClose]);

  const logText = logs.data?.logs ?? "";
  const filteredLogs = logText.split("\n").filter((line) => level === "all" || (level === "warn" ? /\b(WARN|WARNING|ERROR|FATAL)\b/i.test(line) : /\b(ERROR|FATAL)\b/i.test(line))).join("\n");
  const [image, ports = "포트 미공개"] = container.detail.split(" · ");
  const cpu = stats.data?.cpuPercent;
  const used = stats.data?.memoryUsedBytes;
  const limit = stats.data?.memoryLimitBytes;

  return (
    <div className="overlay container-detail-overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className="container-detail-drawer" role="dialog" aria-modal="true" aria-labelledby="container-detail-title" data-container-detail-drawer>
        <div className="container-detail-top">
          <span className="action-dialog__icon"><ScrollText size={19} aria-hidden="true" /></span>
          <div className="heading-actions">
            {tab === "overview" ? <button className="icon-button" onClick={() => stats.refetch()} disabled={stats.isFetching} aria-label="통계 새로고침"><RefreshCw size={15} className={stats.isFetching ? "spin" : ""} /></button> : <><label className="container-log-level">로그 수준<select aria-label="로그 수준 필터" value={level} onChange={(event) => setLevel(event.target.value)}><option value="all">전체</option><option value="warn">WARN+</option><option value="error">ERROR</option></select></label><button className="icon-button" onClick={() => setPaused(!paused)} aria-label={paused ? "로그 재개" : "로그 일시정지"}>{paused ? <Play size={15} /> : <Pause size={15} />}</button><button className="icon-button" onClick={() => logs.refetch()} disabled={logs.isFetching} aria-label="로그 새로고침"><RefreshCw size={15} className={logs.isFetching ? "spin" : ""} /></button></>}
            <button ref={closeRef} className="icon-button" onClick={onClose} aria-label="컨테이너 상세 닫기"><X size={18} /></button>
          </div>
        </div>
        <h2 id="container-detail-title">{container.name}</h2>
        <p className="muted-copy">{mode === "mock" ? "DEMO · 실제 Docker 컨테이너가 아닙니다." : "Portainer · 읽기 전용 컨테이너 상세"}</p>
        <div className="container-detail-tabs" role="group" aria-label="컨테이너 정보">
          <button aria-pressed={tab === "overview"} onClick={() => setTab("overview")}>개요</button>
          <button aria-pressed={tab === "logs"} onClick={() => setTab("logs")}>실시간 로그</button>
        </div>
        {tab === "overview" ? <div className="container-detail-content">
          <section className="container-detail-metrics" aria-label="컨테이너 통계">
            <div><span>CPU</span><strong>{cpu == null ? "—" : `${cpu.toFixed(1)}%`}</strong></div>
            <div><span>메모리</span><strong>{used == null ? "—" : `${formatBytes(used)}${limit ? ` / ${formatBytes(limit)}` : ""}`}</strong><small>{stats.data?.memoryPercent == null ? "" : `${stats.data.memoryPercent.toFixed(1)}%`}</small></div>
          </section>
          {stats.isPending ? <div className="container-logs-state" role="status"><LoaderCircle className="spin" size={16} />통계 불러오는 중</div> : stats.isError ? <div className="container-detail-note" role="alert">통계를 불러오지 못했습니다. {stats.error.message}</div> : stats.data?.status !== "connected" ? <div className="container-detail-note" role="status">{stats.data?.message ?? "통계를 사용할 수 없습니다."}</div> : <div className="container-detail-note" role="status">{stats.data.mode === "mock" ? stats.data.message : "현재 Docker 샘플 · 주기적으로 갱신"}</div>}
          <section className="container-trend" aria-label="컨테이너 사용량 추이"><h3>최근 CPU · 메모리 추이</h3>{history.length > 1 ? <ContainerTrendChart history={history} /> : <p className="container-trend__empty">{stats.data?.mode === "mock" ? "DEMO 통계는 현재 샘플 한 건만 표시합니다." : "Live 측정값이 2회 이상 수집되면 추이를 표시합니다."}</p>}</section>
          <dl className="container-detail-info"><div><dt>상태</dt><dd>{container.status}</dd></div><div><dt>이미지</dt><dd>{image}</dd></div><div><dt>포트</dt><dd>{ports}</dd></div><div><dt>컨테이너 ID</dt><dd className="mono-text">{container.id}</dd></div></dl>
        </div> : <div className="container-detail-content">
          <p className="container-log-state" role="status">{paused ? "일시정지됨" : logs.data?.mode === "mock" ? "DEMO 로그" : "최근 로그 · Live"} · 최대 3초 간격 갱신</p>
          {logs.isPending ? <div className="container-logs-state" role="status"><LoaderCircle className="spin" size={16} />로그 불러오는 중</div> : logs.isError ? <div className="container-logs-state" role="alert"><span>{logs.error.message}</span><button className="button button--small" onClick={() => logs.refetch()}>다시 시도</button></div> : <pre className="container-logs-output" aria-label={`${container.name} 로그`}>{filteredLogs || "표시할 로그가 없습니다."}</pre>}
        </div>}
      </section>
    </div>
  );
}
