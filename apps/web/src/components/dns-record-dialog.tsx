"use client";

import { useEffect, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound, LoaderCircle, X } from "lucide-react";
import { startAuthentication } from "@simplewebauthn/browser";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import { beginPasskeyReauth, createJob, finishPasskeyReauth } from "@/lib/api";
import type { DnsRecordChange, JobRequest, ResourceView } from "@/lib/contracts";
import { useToast } from "@/components/toast-provider";

type Operation = "create" | "update" | "delete";
type RecordValue = NonNullable<DnsRecordChange["before"]>;
export type DnsRecordSelection = { operation: Operation; row?: ResourceView["rows"][number]; initial?: RecordValue };

function sensitiveDnsChange(before?: RecordValue, after?: RecordValue) {
  return [before, after].some((record) => record && (
    record.type === "MX"
    || record.type === "TXT" && (
      record.content.toLowerCase().includes("v=spf1")
      || /_dmarc|_domainkey/i.test(record.name)
    )
  ));
}

function formatRecord(record: RecordValue) {
  return `${record.type} · ${record.name} · ${record.content} · TTL ${record.ttl}${record.type === "MX" ? ` · priority ${record.priority ?? "—"}` : ""}${["A", "AAAA", "CNAME"].includes(record.type) ? ` · Proxy ${record.proxied ? "사용" : "미사용"}` : ""}`;
}

export function DnsRecordDialog({
  selection,
  mode,
  writeEnabled,
  onClose,
}: {
  selection: DnsRecordSelection;
  mode: "mock" | "live";
  writeEnabled: boolean;
  onClose: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const queryClient = useQueryClient();
  const toast = useToast();
  const previous = selection.row?.dnsRecord ?? undefined;
  const initial = selection.initial ?? previous;
  const [name, setName] = useState(initial?.name ?? "");
  const [type, setType] = useState<RecordValue["type"]>(initial?.type ?? "A");
  const [content, setContent] = useState(initial?.content ?? "");
  const [ttl, setTtl] = useState(String(initial?.ttl ?? 1));
  const [priority, setPriority] = useState(String(initial?.priority ?? 10));
  const [proxied, setProxied] = useState(initial?.proxied ?? false);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState("");
  const operation = `dns_${selection.operation}` as Extract<JobRequest["operation"], `dns_${string}`>;
  const after = selection.operation === "delete" ? undefined : {
    name,
    type,
    content,
    ttl: Number(ttl),
    proxied: ["A", "AAAA", "CNAME"].includes(type) && proxied,
    ...(type === "MX" ? { priority: Number(priority) } : {}),
  } satisfies RecordValue;
  const change: DnsRecordChange = {
    ...(selection.row ? { recordId: selection.row.id, before: previous } : {}),
    ...(after ? { after } : {}),
  };
  const sensitive = sensitiveDnsChange(previous, after);
  const actionLabel = selection.operation === "create" ? "추가" : selection.operation === "delete" ? "삭제" : "변경";
  const target = selection.row?.id ?? "zone";
  const mutation = useMutation({
    mutationFn: async () => {
      const request: JobRequest = { operation, target, dnsChange: change };
      if (mode === "mock") return createJob(request);
      if (!writeEnabled) throw new Error("CLOUDFLARE_DNS_WRITE_TOKEN is not configured.");
      if (!window.PublicKeyCredential) throw new Error("이 브라우저는 WebAuthn을 지원하지 않습니다.");
      const challenge = await beginPasskeyReauth({ operation, target, dnsChange: change });
      const credential = await startAuthentication({
        optionsJSON: challenge.options as unknown as PublicKeyCredentialRequestOptionsJSON,
      });
      const grant = await finishPasskeyReauth({ challengeId: challenge.challengeId, credential });
      return createJob({ ...request, reauthGrant: grant.grant });
    },
    onSuccess: (job) => {
      void queryClient.invalidateQueries();
      if (job.state !== "succeeded") {
        setError(job.message);
        return;
      }
      toast(job.simulation ? "DEMO DNS 작업 완료" : "DNS 작업 완료", `${job.target} · ${job.message}`, "success");
      onClose();
    },
    onMutate: () => setError(""),
    onError: (cause: Error) => setError(cause.message),
  });
  const ttlValue = Number(ttl);
  const priorityValue = Number(priority);
  const invalidTtl = !Number.isInteger(ttlValue) || (ttlValue !== 1 && ttlValue < 30) || ttlValue > 86_400;
  const invalidPriority = type === "MX" && (!Number.isInteger(priorityValue) || priorityValue < 0 || priorityValue > 65_535);

  useEffect(() => {
    closeRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !mutation.isPending) onClose();
      if (event.key !== "Tab") return;
      const dialog = document.querySelector<HTMLElement>("[data-dns-dialog]");
      const focusable = dialog?.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), select:not(:disabled), [tabindex='0']");
      if (!focusable?.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [mutation.isPending, onClose]);

  return (
    <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && !mutation.isPending && onClose()}>
      <section className="action-dialog dns-dialog" role="dialog" aria-modal="true" aria-labelledby="dns-dialog-title" data-dns-dialog>
        <div className="action-dialog__top">
          <span className="action-dialog__icon"><KeyRound size={19} aria-hidden="true" /></span>
          <button ref={closeRef} className="icon-button" onClick={onClose} disabled={mutation.isPending} aria-label="창 닫기"><X size={18} /></button>
        </div>
        <h2 id="dns-dialog-title">DNS 레코드 {actionLabel} 확인</h2>
        <p className="muted-copy">{mode === "mock" ? "DEMO 작업입니다. Cloudflare DNS는 변경하지 않습니다." : "변경 내용을 확인한 뒤 Owner Passkey 재인증을 진행합니다."}</p>
        {selection.operation !== "delete" && <div className="dns-form">
          <label className="passkey-field">호스트명 (Zone 내 FQDN)
            <input className="passkey-input" value={name} onChange={(event) => { setConfirmed(false); setName(event.target.value); }} maxLength={255} placeholder="api.example.com" autoComplete="off" disabled={mutation.isPending} />
          </label>
          <label className="passkey-field">레코드 유형
            <select className="passkey-input" value={type} onChange={(event) => { setConfirmed(false); setType(event.target.value as RecordValue["type"]); }} disabled={selection.operation === "update" || mutation.isPending}>
              {["A", "AAAA", "CNAME", "TXT", "MX"].map((value) => <option key={value}>{value}</option>)}
            </select>
          </label>
          <label className="passkey-field">값
            <input className="passkey-input" value={content} onChange={(event) => { setConfirmed(false); setContent(event.target.value); }} maxLength={2048} autoComplete="off" disabled={mutation.isPending} />
          </label>
          <label className="passkey-field">TTL (1은 자동, 30초 이상)
            <input className="passkey-input" type="number" min={1} max={86400} value={ttl} onChange={(event) => { setConfirmed(false); setTtl(event.target.value); }} disabled={mutation.isPending} />
          </label>
          {type === "MX" && <label className="passkey-field">MX 우선순위
            <input className="passkey-input" type="number" min={0} max={65535} value={priority} onChange={(event) => { setConfirmed(false); setPriority(event.target.value); }} disabled={mutation.isPending} />
          </label>}
          {["A", "AAAA", "CNAME"].includes(type) && <label className="dns-checkbox"><input type="checkbox" checked={proxied} onChange={(event) => { setConfirmed(false); setProxied(event.target.checked); }} disabled={mutation.isPending} />Cloudflare Proxy 사용</label>}
        </div>}
        <dl className="action-target dns-change-review">
          <div><dt>작업</dt><dd>{actionLabel}</dd></div>
          {previous && <div><dt>현재 값</dt><dd>{formatRecord(previous)}</dd></div>}
          {after && <div><dt>변경 값</dt><dd>{formatRecord(after)}</dd></div>}
          {selection.operation === "delete" && previous && <div><dt>삭제 대상</dt><dd className="mono-text">{selection.row?.id}</dd></div>}
        </dl>
        {sensitive && <div className="reauth-notice" role="alert">MX, SPF, DKIM 또는 DMARC 레코드 변경은 메일 수신·발신을 중단시킬 수 있습니다. 현재 값을 먼저 확인하세요.</div>}
        {mode === "live" && !writeEnabled && <div className="reauth-notice" role="status">Cloudflare DNS 쓰기 키가 없어 Live 변경은 비활성화되어 있습니다.</div>}
        <label className="dns-checkbox dns-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} disabled={mutation.isPending} />변경 대상과 현재·변경 값을 확인했습니다.</label>
        {error && <p className="inline-error" role="alert">{error}</p>}
        <div className="action-dialog__buttons">
          <button className="button button--secondary" onClick={onClose} disabled={mutation.isPending}>취소</button>
          <button className="button button--primary" disabled={mutation.isPending || !confirmed || mode === "live" && !writeEnabled || !name.trim() || selection.operation !== "delete" && (!content.trim() || invalidTtl || invalidPriority)} onClick={() => mutation.mutate()}>
            {mutation.isPending ? <LoaderCircle className="spin" size={16} /> : <KeyRound size={16} />}
            {mutation.isPending ? "재인증 및 실행 중…" : mode === "mock" ? "모의 변경 실행" : "Passkey 확인 후 실행"}
          </button>
        </div>
      </section>
    </div>
  );
}
