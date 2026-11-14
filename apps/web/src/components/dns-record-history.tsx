"use client";

import { useQuery } from "@tanstack/react-query";
import { RotateCcw } from "lucide-react";
import { z } from "zod";
import { getAudit } from "@/lib/api";
import { DnsRecordValueSchema, type AuditEvent, type ResourceView } from "@/lib/contracts";
import type { DnsRecordSelection } from "@/components/dns-record-dialog";

function formatRecord(record: z.infer<typeof DnsRecordValueSchema>) {
  return `${record.type} ${record.name}: ${record.content} · TTL ${record.ttl}${record.type === "MX" ? ` · 우선순위 ${record.priority ?? "—"}` : ""}${["A", "AAAA", "CNAME"].includes(record.type) ? ` · Proxy ${record.proxied ? "사용" : "미사용"}` : ""}`;
}

const DnsChangeDetailsSchema = z.object({
  before: DnsRecordValueSchema.nullable().optional(),
  after: DnsRecordValueSchema.nullable().optional(),
  recordId: z.string().optional(),
  result: z.object({ id: z.string(), name: z.string().optional() }).passthrough().optional(),
});

function parseDetails(event: AuditEvent) {
  try {
    return DnsChangeDetailsSchema.safeParse(JSON.parse(event.details));
  } catch {
    return { success: false as const };
  }
}

function restoreSelection(event: AuditEvent, details: z.infer<typeof DnsChangeDetailsSchema>): DnsRecordSelection | null {
  if (event.result !== "succeeded" || !details.result?.id) return null;
  const recordId = details.result.id;
  if (!/^[0-9a-fA-F]{32}$/.test(recordId)) return null;
  if (event.operation === "dns_delete" && details.before) {
    return { operation: "create", initial: details.before };
  }
  const current = DnsRecordValueSchema.safeParse(details.result);
  if (!current.success) return null;
  const row: ResourceView["rows"][number] = {
    id: recordId,
    name: current.data.name,
    status: `${current.data.type} · 복구 전 확인 필요`,
    detail: current.data.content,
    updatedAt: event.created_at,
    actions: [],
    dnsRecord: current.data,
  };
  if (event.operation === "dns_create") return { operation: "delete", row };
  if (event.operation === "dns_update" && details.before) {
    return { operation: "update", row, initial: details.before };
  }
  return null;
}

export function DnsRecordHistory({
  writeEnabled,
  onRestore,
}: {
  writeEnabled: boolean;
  onRestore: (selection: DnsRecordSelection) => void;
}) {
  const query = useQuery({
    queryKey: ["audit"],
    queryFn: ({ signal }) => getAudit(signal),
  });
  const events = (query.data ?? []).filter((event) => event.operation.startsWith("dns_")).slice(0, 20);

  return <section className="panel dns-history" aria-label="DNS 변경 기록">
    <div className="panel__head"><div><h2 className="panel__title">DNS 변경 기록</h2><p className="panel__subtitle">최근 20건 · 변경 전후 값과 실행 결과</p></div></div>
    {query.isPending ? <p className="empty-inline" aria-busy="true">감사 기록을 불러오는 중…</p>
        : query.isError ? <p className="inline-error" role="alert">DNS 변경 기록을 불러오지 못했습니다: {query.error.message}</p>
          : events.length === 0 ? <p className="empty-inline">DNS 변경 기록이 없습니다.</p>
            : <ol className="dns-history-list">{events.map((event) => {
              const parsed = parseDetails(event);
              const details = parsed.success ? parsed.data : null;
              const before = details?.before;
              const after = details?.after;
              const restoration = details ? restoreSelection(event, details) : null;
              return <li className="dns-history-item" key={event.id}>
                <div className="dns-history-item__head"><div><strong>{event.target}</strong><span>{new Date(event.created_at).toLocaleString("ko-KR")}</span></div><span className="status-pill">{event.operation.replace("dns_", "")} · {event.result}</span></div>
                <p>{before ? formatRecord(before) : "기존 레코드 없음"}</p>
                <p>{after ? formatRecord(after) : "변경 후 레코드 없음"}</p>
                {restoration && <button className="button button--small" disabled={!writeEnabled} title={!writeEnabled ? "Cloudflare DNS 쓰기 키가 필요합니다." : "복구도 새 Passkey 재인증을 요구합니다."} onClick={() => onRestore(restoration)}><RotateCcw size={13} />이 변경 되돌리기</button>}
              </li>;
            })}</ol>}
  </section>;
}
