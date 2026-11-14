"use client";

import { useMemo, useState } from "react";
import { AlertCircle, ArrowUpRight, RefreshCw } from "lucide-react";
import Link from "next/link";
import { ActionDialog } from "@/components/action-dialog";
import { useJobsQuery, useResourceQuery } from "@/lib/queries";
import { findNavItem } from "@/lib/resources";
import { ResourceSchema } from "@/lib/contracts";
import { z } from "zod";

type Resource = z.infer<typeof ResourceSchema>;
type ResourceAction = Resource["actions"][number];

const deploymentStatuses: Record<string, string> = {
  success: "성공", completed: "완료", in_progress: "실행 중", queued: "대기",
  failure: "실패", cancelled: "취소", timed_out: "시간 초과", action_required: "승인 대기",
};

function DeploymentStatus({ status }: { status: string }) {
  const tone = ["success", "completed"].includes(status) ? "healthy" : ["failure", "timed_out"].includes(status) ? "failed" : status === "in_progress" ? "warning" : "";
  return <span className={`status-label ${tone ? `status-label--${tone}` : ""}`}><i className="status-label__dot" aria-hidden="true" />{deploymentStatuses[status] ?? status}</span>;
}

export function DeploymentPage() {
  const nav = findNavItem("deployments")!;
  const query = useResourceQuery("deployments");
  const [tab, setTab] = useState<"runs" | "jobs">("runs");
  const jobs = useJobsQuery(tab === "jobs");
  const [projectId, setProjectId] = useState("");
  const [runId, setRunId] = useState("");
  const [action, setAction] = useState<ResourceAction | null>(null);
  const projects = useMemo(() => {
    const grouped = new Map<string, Resource["rows"]>();
    for (const row of query.data?.rows ?? []) {
      const project = row.id.includes("#") ? row.id.slice(0, row.id.lastIndexOf("#")) : "DEMO";
      grouped.set(project, [...(grouped.get(project) ?? []), row]);
    }
    return [...grouped].map(([id, runs]) => [id, runs.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))] as const);
  }, [query.data?.rows]);

  if (query.isPending) return <div className="page-content"><section className="panel resource-summary skeleton" aria-busy="true" style={{ height: 90 }} /><section className="panel deployment-panel skeleton" aria-hidden="true" /></div>;
  if (query.isError) return <div className="page-content"><div className="page-heading"><div><h1>{nav.label}</h1><p>{nav.subtitle}</p></div><button className="button" onClick={() => query.refetch()}><RefreshCw size={14} />다시 연결</button></div><section className="state-card" role="alert"><span className="state-card__icon"><AlertCircle size={20} /></span><h2>배포 정보를 불러올 수 없습니다</h2><p>{query.error.message}</p></section></div>;

  const data = query.data;
  const selectedProject = projects.find(([id]) => id === projectId) ?? projects[0];
  const selectedRun = selectedProject?.[1].find((run) => run.id === runId) ?? selectedProject?.[1][0];
  const runNumber = selectedRun?.id.slice(selectedRun.id.lastIndexOf("#") + 1);
  const runHref = selectedProject && selectedProject[0] !== "DEMO" && runNumber && /^\d+$/.test(runNumber)
    ? `https://github.com/${selectedProject[0].split("/").map(encodeURIComponent).join("/")}/actions/runs/${runNumber}`
    : null;

  return <div className="page-content">
    <div className="page-heading"><div><h1>{nav.label}</h1><p>{nav.subtitle}</p></div><div className="heading-actions"><span className="status-pill">{data.mode === "mock" ? "DEMO" : data.status === "connected" ? "Live · 읽기 전용" : data.status === "partial" ? "부분 연결" : data.status === "unavailable" ? "응답 없음" : "미연결"}</span><button className="button" onClick={() => query.refetch()} disabled={query.isFetching} aria-label="배포 새로고침"><RefreshCw size={14} className={query.isFetching ? "spin" : ""} /><span>새로고침</span></button></div></div>
    <div className="resource-grid">
      <section className="panel resource-summary" aria-label="배포 요약">{(data.metrics.length ? data.metrics : [{ label: "연결", value: data.status === "not_configured" ? "미연결" : "사용 불가", detail: "공급자 상태" }, { label: "프로젝트", value: "0", detail: "표시할 항목 없음" }, { label: "권한", value: "읽기 전용", detail: "Actions API" }, { label: "환경", value: data.mode === "mock" ? "DEMO" : "Live", detail: "응답 출처" }]).slice(0, 4).map((metric) => <div className="resource-summary__item" key={metric.label}><div className="resource-summary__label">{metric.label}</div><div className="resource-summary__value">{metric.value}</div><div className="panel__subtitle">{metric.detail}</div></div>)}</section>
      <section className="panel deployment-panel resource-table-panel">
        <div className="deployment-tabs" role="group" aria-label="배포 화면"><button className="button button--small" aria-pressed={tab === "runs"} onClick={() => setTab("runs")}>워크플로 실행 <span className="mono-text">{data.rows.length}</span></button><button className="button button--small" aria-pressed={tab === "jobs"} onClick={() => setTab("jobs")}>관리 작업 이력</button></div>
        {tab === "runs" ? <div className="deployment-layout">
          <aside className="deployment-projects" aria-label="프로젝트 목록"><div className="deployment-section-title">프로젝트 <span className="mono-text">{projects.length}</span></div>{projects.length ? projects.map(([id, runs]) => <button type="button" key={id} className="deployment-project" aria-pressed={id === (selectedProject?.[0] ?? "")} onClick={() => { setProjectId(id); setRunId(runs[0]?.id ?? ""); }}><strong>{id === "DEMO" ? "현재 릴리스 · DEMO" : id}</strong><span>{runs.length}개 실행 · <DeploymentStatus status={runs[0]?.status ?? "unknown"} /></span></button>) : <p className="empty-inline">{data.message}</p>}</aside>
          <div className="deployment-main">
            {selectedProject && <><div className="deployment-section-title">실행 목록 <span className="mono-text">{selectedProject[1].length}</span></div><div className="deployment-run-list">{selectedProject[1].map((run) => <button type="button" key={run.id} className="deployment-run" aria-pressed={run.id === (selectedRun?.id ?? "")} onClick={() => setRunId(run.id)}><span><strong>{run.name.split(" · ").slice(1).join(" · ") || run.name}</strong><small>{run.detail}</small></span><DeploymentStatus status={run.status} /></button>)}</div>
              {selectedRun && <section className="deployment-run-detail" aria-label="선택한 실행 상세"><div className="deployment-run-detail__head"><div><span className="resource-summary__label">선택한 실행</span><h2>{selectedRun.name.split(" · ").slice(1).join(" · ") || selectedRun.name}</h2></div><DeploymentStatus status={selectedRun.status} /></div><dl><div><dt>요약</dt><dd>{selectedRun.detail}</dd></div><div><dt>마지막 갱신</dt><dd>{new Date(selectedRun.updatedAt).toLocaleString("ko-KR")}</dd></div><div><dt>실행 결과</dt><dd>{data.mode === "mock" ? "DEMO · 실제 GitHub 실행이 아닙니다." : "GitHub Actions · 읽기 전용"}</dd></div></dl>{runHref && <Link className="button button--small" href={runHref} target="_blank" rel="noreferrer">GitHub에서 보기 <ArrowUpRight size={13} /></Link>}{data.mode === "mock" && data.actions.map((item) => <button type="button" className="button button--small deployment-demo-action" key={item.id} disabled={!item.enabled} title={item.reason} onClick={() => setAction(item)}>{item.label}</button>)}</section>}
            </>}
            {!selectedProject && <div className="empty-inline">{data.message || "표시할 workflow 실행이 없습니다."}</div>}
          </div>
        </div> : jobs.isPending ? <div className="empty-inline" role="status">관리 작업 이력을 불러오는 중입니다.</div> : jobs.isError ? <div className="empty-inline" role="alert">작업 이력 조회 실패 · {jobs.error.message}</div> : jobs.data.length ? <div className="table-scroll"><table className="resource-table" aria-label="작업 이력"><thead><tr><th>작업</th><th>상태</th><th>대상 · 결과</th><th>생성</th></tr></thead><tbody>{jobs.data.map((job) => <tr key={job.id}><td>{job.operation}</td><td>{job.simulation ? "DEMO · " : ""}{job.state}</td><td>{job.target} · {job.message}</td><td className="mono-text">{new Date(job.createdAt).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}</td></tr>)}</tbody></table></div> : <div className="empty-inline">저장된 관리 작업이 없습니다.</div>}
      </section>
      {data.mode === "live" && <div className="resource-note">{data.status === "connected" ? "Live GitHub Actions는 현재 읽기 전용입니다. 실제 workflow 실행과 로그 조회는 GitHub 연결 권한 및 제한된 실행 경로가 준비될 때까지 제공하지 않습니다." : data.message}</div>}
    </div>
    {action && <ActionDialog action={action} mode={data.mode} onClose={() => setAction(null)} />}
  </div>;
}
