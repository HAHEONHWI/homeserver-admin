"use client";

import { useCallback, useMemo, useState } from "react";
import { AlertCircle, ArrowDown, ArrowUp, Database, HardDrive, RefreshCw, Search, Settings2, Shield, Unplug } from "lucide-react";
import Link from "next/link";
import { useResourceQuery } from "@/lib/queries";
import { findNavItem } from "@/lib/resources";
import { ActionDialog } from "@/components/action-dialog";
import { ContainerLogsDialog } from "@/components/container-logs-dialog";
import { DnsRecordDialog, type DnsRecordSelection } from "@/components/dns-record-dialog";
import { DnsRecordHistory } from "@/components/dns-record-history";
import { DeploymentPage } from "@/components/deployment-page";
import { PasskeyManager } from "@/components/passkey-manager";
import type { ResourceView } from "@/lib/contracts";

const unavailableIcon = { database: Database, storage: HardDrive, security: Shield, settings: Settings2 } as const;
const serviceStatusLabels: Record<string, string> = { healthy: "정상", warning: "주의", failed: "오류", stopped: "중지", not_configured: "미연결" };
const emptyText: Record<string, string> = {
  services: "Portainer가 연결되면 컨테이너 Healthcheck 상태가 표시됩니다.", notifications: "알림 공급자를 연결하면 최근 이벤트가 표시됩니다.", system: "호스트 에이전트가 연결되지 않았습니다.", automation: "자동화 공급자가 구성되지 않았습니다.", domains: "DNS 제공자가 구성되지 않았습니다.", mail: "메일 제공자가 구성되지 않았습니다.", database: "데이터베이스 연결 정보가 구성되지 않았습니다.", storage: "호스트 스토리지 에이전트가 연결되지 않았습니다.", monitoring: "모니터링 공급자가 구성되지 않았습니다.", security: "인증 상태는 Cloudflare Access에서 확인합니다. 감사 저장소가 연결되지 않았습니다.", settings: "관리할 외부 연결이 구성되지 않았습니다.", containers: "컨테이너 에이전트가 연결되지 않았습니다.", images: "Portainer가 연결되면 Docker 이미지와 태그가 표시됩니다.", stacks: "Portainer가 연결되면 Compose stack 목록이 표시됩니다.", deployments: "배포 공급자가 구성되지 않았습니다.",
};

function ResourceStatus({ status }: { status: string }) {
  const label = serviceStatusLabels[status];
  if (!label) return <>{status}</>;
  const tone = ["healthy", "warning", "failed"].includes(status) ? `status-label--${status}` : "";
  return <span className={`status-label ${tone}`}><i className="status-label__dot" aria-hidden="true" />{label}</span>;
}

function containerStatusCategory(status: string) {
  const normalized = status.toLocaleLowerCase("en-US");
  if (normalized.includes("demo")) return "demo";
  if (/\b(unhealthy|restarting|dead|error)\b/.test(normalized)) return "error";
  if (/\bpaused\b/.test(normalized)) return "paused";
  if (/^(up|running)\b/.test(normalized)) return "running";
  if (/^(exited|stopped|created)\b/.test(normalized)) return "stopped";
  return "error";
}

export function ResourcePage({ resourceKey }: { resourceKey: string }) {
  return resourceKey === "deployments" ? <DeploymentPage /> : <ResourcePageContent resourceKey={resourceKey} />;
}

function ResourcePageContent({ resourceKey }: { resourceKey: string }) {
  const nav = findNavItem(resourceKey);
  const query = useResourceQuery(resourceKey);
  const [action, setAction] = useState<null | ResourceView["actions"][number]>(null);
  const [dnsAction, setDnsAction] = useState<DnsRecordSelection | null>(null);
  const [logsContainer, setLogsContainer] = useState<null | { id: string; name: string; status: string; detail: string; initialTab: "overview" | "logs" }>(null);
  const [containerSearch, setContainerSearch] = useState("");
  const [containerFilter, setContainerFilter] = useState("all");
  const [containerSort, setContainerSort] = useState<"name" | "status" | "updatedAt">("name");
  const [sortAscending, setSortAscending] = useState(true);
  const closeContainerDetail = useCallback(() => setLogsContainer(null), []);
  const containerRows = useMemo(() => {
    const rows = query.data?.rows ?? [];
    if (resourceKey !== "containers") return rows;
    const search = containerSearch.trim().toLocaleLowerCase("ko-KR");
    return rows.filter((row) => {
      const state = containerStatusCategory(row.status);
      return (containerFilter === "all" || state === containerFilter || (containerFilter === "stopped" && state === "paused"))
        && (!search || `${row.name} ${row.status} ${row.detail}`.toLocaleLowerCase("ko-KR").includes(search));
    }).sort((a, b) => {
      const order = containerSort === "updatedAt"
        ? a.updatedAt.localeCompare(b.updatedAt)
        : a[containerSort].localeCompare(b[containerSort], "ko-KR", { numeric: true, sensitivity: "base" });
      return order * (sortAscending ? 1 : -1);
    });
  }, [containerFilter, containerSearch, containerSort, query.data?.rows, resourceKey, sortAscending]);
  if (!nav) return null;
  const Icon = nav.icon;
  const IntegrationIcon = unavailableIcon[resourceKey as keyof typeof unavailableIcon] ?? Unplug;

  if (query.isPending) return <div className="page-content"><div className="page-heading"><div><h1>{nav.label}</h1><p>{nav.subtitle}</p></div></div><div className="resource-grid" aria-busy="true"><div className="panel resource-summary"><div className="resource-summary__item skeleton" /><div className="resource-summary__item skeleton" /><div className="resource-summary__item skeleton" /><div className="resource-summary__item skeleton" /></div><div className="panel resource-table-panel skeleton" style={{ height: 210 }} /></div></div>;
  if (query.isError) return <div className="page-content"><div className="page-heading"><div><h1>{nav.label}</h1><p>{nav.subtitle}</p></div><button className="button" onClick={() => query.refetch()}><RefreshCw size={14} />다시 연결</button></div><section className="state-card" role="alert"><span className="state-card__icon"><AlertCircle size={20} /></span><h2>정보를 불러올 수 없습니다</h2><p>{query.error.message}</p></section></div>;

  const data = query.data;
  const isUnavailable = data.status === "not_configured" || data.status === "unavailable";
  const hasActions = data.actions.length > 0 || data.rows.some((row) => row.actions.length > 0)
    || resourceKey === "domains" && data.rows.some((row) => row.dnsRecord !== null && row.dnsRecord !== undefined);
  const connectionLabel = data.mode === "mock" ? "DEMO" : data.status === "partial" ? "부분 연결" : isUnavailable ? "미연결" : "연결";
  const metrics = data.metrics.length ? data.metrics : [{ label: "연결 상태", value: "미연결", detail: "공급자 설정 대기" }, { label: "환경", value: data.mode === "mock" ? "DEMO" : "Live", detail: "응답 출처" }, { label: "리소스", value: "0", detail: "표시할 항목 없음" }, { label: "최근 갱신", value: new Date(data.updatedAt).toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit" }), detail: "API 응답" }];
  return <div className="page-content">
    <div className="page-heading"><div><h1>{nav.label}</h1><p>{nav.subtitle}</p></div><div className="heading-actions"><span className="status-pill"><i className="status-pill__dot" aria-hidden="true" />{connectionLabel}</span><button className="button" onClick={() => query.refetch()} disabled={query.isFetching} aria-label="정보 새로고침"><RefreshCw size={14} className={query.isFetching ? "spin" : ""} /><span>새로고침</span></button></div></div>
    <div className="resource-grid">
      {["containers", "stacks", "images"].includes(resourceKey) && <nav className="resource-tabs" aria-label="Docker 리소스"><Link href="/containers" aria-current={resourceKey === "containers" ? "page" : undefined}>컨테이너</Link><Link href="/stacks" aria-current={resourceKey === "stacks" ? "page" : undefined}>Compose 스택</Link><Link href="/images" aria-current={resourceKey === "images" ? "page" : undefined}>이미지</Link></nav>}
      <section className="panel resource-summary" aria-label="요약">{metrics.slice(0, 4).map((metric) => <div className="resource-summary__item" key={metric.label}><div className="resource-summary__label">{metric.label}</div><div className="resource-summary__value">{metric.value}</div><div className="panel__subtitle">{metric.detail}</div></div>)}</section>
      {isUnavailable && <section className="state-card resource-note" role="status"><span className="state-card__icon"><IntegrationIcon size={20} /></span><h2>{data.status === "not_configured" ? "공급자가 연결되지 않았습니다" : "공급자 응답이 없습니다"}</h2><p>{data.message || emptyText[resourceKey]}</p></section>}
      {data.status === "partial" && <div className="resource-note" role="status">{data.message}</div>}
      {resourceKey === "security" && <PasskeyManager />}
      <section className="panel resource-table-panel">
        <div className="panel__head"><div><h2 className="panel__title">{isUnavailable ? "연결 정보" : "리소스"}</h2><p className="panel__subtitle">{data.rows.length}개 항목 · {data.mode === "mock" ? "모의 데이터" : "Live 응답"}</p></div><div className="heading-actions">{resourceKey === "domains" && <button className="button button--small" disabled={data.mode === "live" && !data.writeEnabled} title={data.mode === "live" && !data.writeEnabled ? "Cloudflare DNS 쓰기 키가 필요합니다." : undefined} onClick={() => setDnsAction({ operation: "create" })}>DNS 추가</button>}<Icon size={15} className="metric-card__icon" /></div></div>
        {resourceKey === "containers" && <div className="container-controls"><label className="container-search"><Search size={14} aria-hidden="true" /><span className="sr-only">컨테이너 검색</span><input value={containerSearch} onChange={(event) => setContainerSearch(event.target.value)} placeholder="컨테이너, 이미지, 포트 검색" /></label><div className="container-filters" aria-label="컨테이너 상태 필터">{[["all", "전체"], ["running", "실행 중"], ["stopped", "중지"], ["error", "문제"]].map(([key, label]) => <button type="button" key={key} className="button button--small" aria-pressed={containerFilter === key} onClick={() => setContainerFilter(key)}>{label} <span className="mono-text">{key === "all" ? data.rows.length : data.rows.filter((row) => { const category = containerStatusCategory(row.status); return category === key || (key === "stopped" && category === "paused"); }).length}</span></button>)}</div><div className="container-sort">정렬 {(["name", "status", "updatedAt"] as const).map((key) => <button key={key} className="button button--small button--secondary" aria-pressed={containerSort === key} onClick={() => { if (containerSort === key) setSortAscending(!sortAscending); else { setContainerSort(key); setSortAscending(true); } }}>{key === "name" ? "이름" : key === "status" ? "상태" : "갱신"}{containerSort === key && (sortAscending ? <ArrowUp size={12} /> : <ArrowDown size={12} />)}</button>)}</div></div>}
        {data.rows.length ? <div className={`table-scroll${resourceKey === "containers" ? " container-table-scroll" : ""}`}><table className="resource-table"><thead><tr>{data.columns.map((column) => <th key={column}>{column}</th>)}{hasActions && <th>작업</th>}{resourceKey === "containers" && <th>로그</th>}</tr></thead><tbody>{(resourceKey === "containers" ? containerRows : data.rows).map((row) => <tr key={row.id}>
          <td data-label={data.columns[0]}>{resourceKey === "containers" ? <button className="container-name-button" onClick={() => setLogsContainer({ id: row.id, name: row.name, status: row.status, detail: row.detail, initialTab: "overview" })}>{row.name}</button> : row.name}</td>
          <td data-label={data.columns[1]}>{resourceKey === "services" ? <ResourceStatus status={row.status} /> : resourceKey === "containers" ? <span className={`container-state container-state--${containerStatusCategory(row.status)}`}>{containerStatusCategory(row.status) === "demo" ? "DEMO" : containerStatusCategory(row.status) === "running" ? "실행 중" : containerStatusCategory(row.status) === "paused" ? "일시 중지" : containerStatusCategory(row.status) === "stopped" ? "중지" : "문제"}</span> : row.status}</td>
          <td data-label={data.columns[2]}>{row.detail}</td>
          <td data-label={data.columns[3]} className="mono-text">{new Date(row.updatedAt).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}</td>
          {hasActions && <td data-label="작업">{row.actions.map((item) => <button className="button button--small" key={item.id} disabled={!item.enabled} title={item.reason} onClick={() => setAction(item)}>{item.label}</button>)}{data.actions.map((item) => <button className="button button--small" key={item.id} disabled={!item.enabled || data.mode !== "mock"} title={item.reason} onClick={() => setAction(item)}>{item.label}</button>)}{resourceKey === "domains" && row.dnsRecord && <><button className="button button--small" disabled={data.mode === "live" && !data.writeEnabled} onClick={() => setDnsAction({ operation: "update", row })}>편집</button><button className="button button--small" disabled={data.mode === "live" && !data.writeEnabled} onClick={() => setDnsAction({ operation: "delete", row })}>삭제</button></>}</td>}
          {resourceKey === "containers" && <td data-label="로그"><button className="button button--small" onClick={() => setLogsContainer({ id: row.id, name: row.name, status: row.status, detail: row.detail, initialTab: "logs" })} disabled={data.mode === "live" && !/^[a-fA-F0-9]{12,64}$/.test(row.id)}>로그 보기</button></td>}
        </tr>)}</tbody></table></div> : <div className="empty-inline">{data.message || emptyText[resourceKey]}</div>}
        {resourceKey === "containers" && data.rows.length > 0 && containerRows.length === 0 && <div className="empty-inline">검색 또는 상태 조건에 맞는 컨테이너가 없습니다.</div>}
      </section>
      {resourceKey === "containers" && data.mode === "live" && data.status === "connected" && <div className="resource-note" role="status">{data.message}</div>}
      {resourceKey === "domains" && data.mode === "live" && data.status === "connected" && <div className="resource-note" role="status">{data.message}</div>}
      {resourceKey === "domains" && <DnsRecordHistory writeEnabled={data.writeEnabled} onRestore={setDnsAction} />}
      {data.actions.length > 0 && <div className="resource-note">{data.mode === "mock" ? "DEMO 작업은 API에서 모의 결과와 감사 이벤트만 기록합니다." : "Live 작업은 검증된 서버 에이전트와 재인증이 준비될 때까지 비활성화됩니다."}</div>}
    </div>
    {action && <ActionDialog action={action} mode={data.mode} onClose={() => setAction(null)} />}
    {dnsAction && <DnsRecordDialog selection={dnsAction} mode={data.mode} writeEnabled={data.writeEnabled} onClose={() => setDnsAction(null)} />}
    {logsContainer && <ContainerLogsDialog container={logsContainer} mode={data.mode} initialTab={logsContainer.initialTab} onClose={closeContainerDetail} />}
  </div>;
}
