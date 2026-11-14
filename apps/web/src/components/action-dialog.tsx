"use client";

import { useEffect, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound, LoaderCircle, X } from "lucide-react";
import { startAuthentication } from "@simplewebauthn/browser";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import { beginPasskeyReauth, createJob, finishPasskeyReauth } from "@/lib/api";
import type { JobRequest, ResourceView } from "@/lib/contracts";
import { useToast } from "@/components/toast-provider";

type Action = ResourceView["actions"][number] | { id: string; label: string; operation: JobRequest["operation"]; target: string; targetLabel?: string | null; enabled: boolean; reason: string };

function isContainerOperation(operation: JobRequest["operation"]): operation is "start" | "stop" | "restart" {
  return operation === "start" || operation === "stop" || operation === "restart";
}

export function ActionDialog({ action, mode, onClose }: { action: Action; mode: "mock" | "live"; onClose: () => void }) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const queryClient = useQueryClient();
  const toast = useToast();
  const [error, setError] = useState("");
  const liveContainerAction = mode === "live" && isContainerOperation(action.operation) && action.enabled;
  const mutation = useMutation({
    mutationFn: async () => {
      const job = { operation: action.operation, target: action.target };
      if (mode === "mock") return createJob(job);
      if (!liveContainerAction || !isContainerOperation(action.operation)) throw new Error("Live container action is unavailable.");
      if (!window.PublicKeyCredential) throw new Error("이 브라우저는 WebAuthn을 지원하지 않습니다.");
      const challenge = await beginPasskeyReauth({ operation: action.operation, target: action.target });
      const credential = await startAuthentication({
        optionsJSON: challenge.options as unknown as PublicKeyCredentialRequestOptionsJSON,
      });
      const grant = await finishPasskeyReauth({ challengeId: challenge.challengeId, credential });
      return createJob({ ...job, reauthGrant: grant.grant });
    },
    onSuccess: (job) => {
      void queryClient.invalidateQueries();
      if (job.state !== "succeeded") {
        setError(job.message);
        return;
      }
      toast(job.simulation ? "DEMO 작업 완료" : "작업 완료", `${job.target} · ${job.message}`, "success");
      onClose();
    },
    onError: (cause: Error) => setError(cause.message),
  });

  useEffect(() => {
    cancelRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !mutation.isPending) onClose();
      if (event.key !== "Tab") return;
      const dialog = document.querySelector<HTMLElement>("[data-action-dialog]");
      const focusable = dialog?.querySelectorAll<HTMLElement>('button:not(:disabled), [href], input:not(:disabled)');
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
      <section className="action-dialog" role="dialog" aria-modal="true" aria-labelledby="action-title" data-action-dialog>
        <div className="action-dialog__top">
          <span className="action-dialog__icon"><KeyRound size={19} aria-hidden="true" /></span>
          <button className="icon-button" onClick={onClose} disabled={mutation.isPending} aria-label="창 닫기"><X size={18} /></button>
        </div>
        <h2 id="action-title">{action.label} 확인</h2>
        <p className="muted-copy">{mode === "mock" ? "대상과 작업을 확인하세요. Demo 작업은 실제 서버 명령을 호출하지 않습니다." : liveContainerAction ? "대상과 작업을 확인하세요. 실행 전 이 대상에 한 번만 사용할 수 있는 Passkey 재인증을 진행합니다." : "이 Live 작업은 검증된 제한 실행기가 구성될 때까지 차단됩니다."}</p>
        <dl className="action-target">
          <div><dt>작업</dt><dd>{action.label}</dd></div>
          <div><dt>대상</dt><dd>{action.targetLabel ?? action.target}</dd></div>
          {action.targetLabel && <div><dt>Container ID</dt><dd className="mono-text">{action.target}</dd></div>}
        </dl>
        <div className={`reauth-notice ${mode === "mock" ? "reauth-notice--demo" : ""}`}>
          {mode === "mock" ? "DEMO · 모의 인증과 가상 작업만 실행됩니다. 실제 서버 명령은 호출하지 않습니다." : liveContainerAction ? "실행 시 Passkey 확인을 거쳐 지정된 컨테이너 작업만 요청합니다." : "Live 서버 작업에는 설정된 제한 실행기와 권한이 필요합니다."}
        </div>
        {error && <p className="inline-error" role="alert">{error}</p>}
        <div className="action-dialog__buttons">
          <button ref={cancelRef} className="button button--secondary" onClick={onClose} disabled={mutation.isPending}>취소</button>
          <button
            className="button button--primary"
            disabled={mutation.isPending || !action.enabled || (mode !== "mock" && !liveContainerAction)}
            onClick={() => mutation.mutate()}
          >
            {mutation.isPending ? <LoaderCircle className="spin" size={16} /> : <KeyRound size={16} />}
            {mutation.isPending ? "재인증 및 실행 중…" : mode === "mock" ? "모의 작업 실행" : liveContainerAction ? "Passkey 확인 후 실행" : "실행 차단됨"}
          </button>
        </div>
      </section>
    </div>
  );
}

