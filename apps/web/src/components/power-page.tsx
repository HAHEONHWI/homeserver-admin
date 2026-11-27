"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import { useQueryClient } from "@tanstack/react-query";
import { KeyRound, LoaderCircle, Power, RefreshCw, Server, Trash2, X } from "lucide-react";
import { ApiError, isPcOffline } from "@/lib/api";
import {
  beginPowerPasskey,
  beginPowerReauth,
  deletePowerPasskey,
  finishPowerPasskey,
  finishPowerReauth,
  queuePowerCommand,
  type PowerPasskey,
  type PowerStatus,
} from "@/lib/power-client";
import { useOverviewQuery, usePowerStatusQuery } from "@/lib/queries";
import { useToast } from "@/components/toast-provider";

const stateLabel = { on: "켜짐", off: "꺼짐", unknown: "확인 불가", offline: "응답 없음" } as const;
const kindLabel: Record<string, string> = {
  queue: "대기", replace: "교체", deliver: "전달", expire: "만료", ack: "응답", reject: "거절", enroll: "Passkey 등록", remove: "Passkey 삭제",
};

export function PowerPage() {
  const status = usePowerStatusQuery();
  const overview = useOverviewQuery();
  const pcOffline = overview.isError && isPcOffline(overview.error);
  const pcLabel = overview.isPending ? "PC 연결 확인 중" : pcOffline ? "PC 꺼짐" : overview.isError ? "관리 API 응답 없음" : overview.data?.mode === "mock" ? "DEMO 모드" : "PC 관리 API 연결";

  return <div className="page-content">
    <div className="page-heading">
      <div><h1>전원</h1><p>ESP32가 전원 버튼을 짧게 누르고, PC가 꺼져 있어도 이 화면은 유지됩니다.</p></div>
      <div className="heading-actions">
        <span className="status-pill"><i className="status-pill__dot" aria-hidden="true" />{pcLabel}</span>
        <button className="button" onClick={() => { void status.refetch(); void overview.refetch(); }} disabled={status.isFetching} aria-label="전원 상태 새로고침"><RefreshCw size={14} className={status.isFetching ? "spin" : ""} /><span>새로고침</span></button>
      </div>
    </div>
    {pcOffline && <section className="state-banner" role="status"><Server size={14} /><span>관리 API에 연결할 수 없습니다. PC가 꺼져 있거나 터널이 내려가 있을 수 있습니다. 전원 제어는 계속 사용할 수 있습니다.</span></section>}
    {status.isPending && <div className="resource-grid" aria-busy="true"><div className="panel resource-summary"><div className="resource-summary__item skeleton" /><div className="resource-summary__item skeleton" /><div className="resource-summary__item skeleton" /><div className="resource-summary__item skeleton" /></div></div>}
    {status.isError && <PowerError error={status.error} onRetry={() => void status.refetch()} />}
    {status.data && <PowerConsole status={status.data} pcOffline={pcOffline} />}
  </div>;
}

function PowerError({ error, onRetry }: { error: Error; onRetry: () => void }) {
  const status = error instanceof ApiError ? error.status : 0;
  const title = status === 403 ? "소유자만 전원을 제어할 수 있습니다" : status === 401 ? "Cloudflare Access 로그인이 필요합니다" : "전원 상태를 불러올 수 없습니다";
  return <section className="state-card" role="alert"><span className="state-card__icon"><Power size={20} /></span><h2>{title}</h2><p>{error.message}</p><button className="button" onClick={onRetry}>다시 시도</button></section>;
}

function PowerConsole({ status, pcOffline }: { status: PowerStatus; pcOffline: boolean }) {
  const [action, setAction] = useState<"power_on" | "power_off" | null>(null);
  const seen = status.device.seenAt ? new Date(status.device.seenAt).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "없음";
  return <div className="resource-grid">
    <section className="panel resource-summary" aria-label="전원 요약">
      <div className="resource-summary__item"><div className="resource-summary__label">PC 관리 API</div><div className="resource-summary__value">{pcOffline ? "꺼짐" : "연결"}</div><div className="panel__subtitle">{pcOffline ? "메트릭과 Docker는 숨김" : "FastAPI 응답"}</div></div>
      <div className="resource-summary__item"><div className="resource-summary__label">ESP32</div><div className="resource-summary__value">{status.configured ? (status.device.online ? "온라인" : "오프라인") : "미구성"}</div><div className="panel__subtitle">{status.deviceId ?? "장치 ID 없음"}</div></div>
      <div className="resource-summary__item"><div className="resource-summary__label">보고된 전원</div><div className="resource-summary__value">{stateLabel[status.device.state]}</div><div className="panel__subtitle">{status.device.firmware || "펌웨어 정보 없음"}</div></div>
      <div className="resource-summary__item"><div className="resource-summary__label">마지막 응답</div><div className="resource-summary__value">{seen}</div><div className="panel__subtitle">{status.pending ? "명령 대기 중" : status.inflight ? "전달 후 응답 대기" : `명령 유지 ${status.commandTtlSeconds}초`}</div></div>
    </section>
    {!status.configured && <section className="state-card resource-note" role="status"><span className="state-card__icon"><Power size={20} /></span><h2>전원 장치가 구성되지 않았습니다</h2><p>Vercel에 장치 비밀과 Upstash Redis를 설정하고, ESP32 config.h에 같은 비밀을 넣은 뒤 다시 확인하세요.</p></section>}
    {status.configured && !status.device.online && <div className="resource-note" role="status">ESP32가 최근 90초 안에 응답하지 않았습니다. 명령은 {status.commandTtlSeconds}초 후 사라집니다.</div>}
    <section className="panel resource-table-panel">
      <div className="panel__head"><div><h2 className="panel__title">전원 동작</h2><p className="panel__subtitle">소유자 Passkey로 한 번 확인한 명령만 ESP32에 전달됩니다.</p></div></div>
      <div className="power-actions">
        <button className="button button--primary" disabled={!status.configured || status.bootstrapRequired} onClick={() => setAction("power_on")}><Power size={14} />전원 켜기</button>
        <button className="button" disabled={!status.configured || status.bootstrapRequired} onClick={() => setAction("power_off")}>전원 끄기</button>
      </div>
      {status.bootstrapRequired && <p className="passkey-help">전원 명령을 보내려면 먼저 이 계정의 Passkey를 등록하세요. PC가 꺼져 있어도 등록은 이 페이지에서 진행합니다.</p>}
    </section>
    <PowerPasskeys status={status} />
    <section className="panel resource-table-panel">
      <div className="panel__head"><div><h2 className="panel__title">전원 감사</h2><p className="panel__subtitle">최근 {status.audit.length}개 · 장치 비밀은 표시하지 않습니다</p></div></div>
      {status.audit.length ? <div className="table-scroll"><table className="resource-table"><thead><tr><th>시각</th><th>주체</th><th>기록</th><th>결과</th></tr></thead><tbody>{status.audit.map((event) => <tr key={event.id}><td className="mono-text">{new Date(event.at).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" })}</td><td>{event.actor}</td><td>{kindLabel[event.kind] ?? event.kind}{event.action ? ` · ${event.action === "power_on" ? "켜기" : "끄기"}` : ""}</td><td>{event.result ?? event.detail ?? "—"}</td></tr>)}</tbody></table></div> : <div className="empty-inline">아직 전원 기록이 없습니다.</div>}
    </section>
    {action && <PowerDialog action={action} deviceId={status.deviceId ?? "home-pc"} onClose={() => setAction(null)} />}
  </div>;
}

function PowerPasskeys({ status }: { status: PowerStatus }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [bootstrapToken, setBootstrapToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function enroll(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    const token = bootstrapToken;
    setBootstrapToken("");
    try {
      if (!window.PublicKeyCredential) throw new Error("이 브라우저는 WebAuthn을 지원하지 않습니다.");
      const grant = status.bootstrapRequired ? undefined : (await reauthenticate("register_passkey", "account")).grant;
      const challenge = await beginPowerPasskey({
        name: name.trim() || "내 기기",
        ...(status.bootstrapRequired ? { bootstrapToken: token } : { reauthGrant: grant }),
      });
      const credential = await startRegistration({ optionsJSON: challenge.options as PublicKeyCredentialCreationOptionsJSON });
      await finishPowerPasskey({ challengeId: challenge.challengeId, credential });
      setName("");
      await queryClient.invalidateQueries({ queryKey: ["power-status"] });
      toast("Passkey 등록 완료", "전원 확인에 사용할 Passkey를 추가했습니다.", "success");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Passkey 등록에 실패했습니다.");
    } finally {
      setBusy(false);
    }
  }

  async function remove(passkey: PowerPasskey) {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const grant = await reauthenticate("delete_passkey", passkey.id);
      await deletePowerPasskey({ credentialId: passkey.id, reauthGrant: grant.grant });
      await queryClient.invalidateQueries({ queryKey: ["power-status"] });
      toast("Passkey 삭제 완료", `${passkey.name} Passkey를 삭제했습니다.`, "success");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Passkey 삭제에 실패했습니다.");
    } finally {
      setBusy(false);
    }
  }

  return <section className="panel passkey-panel" aria-labelledby="power-passkey-title">
    <div className="panel__head"><div><h2 className="panel__title" id="power-passkey-title">전원 Passkey</h2><p className="panel__subtitle">PC의 대시보드 Passkey와 별도로, Vercel 저장소에 공개키만 보관합니다.</p></div></div>
    {status.passkeys.length ? <ul className="passkey-list">{status.passkeys.map((passkey) => <li className="passkey-row" key={passkey.id}><span className="passkey-row__identity"><strong>{passkey.name}</strong><span className="mono-text">{new Date(passkey.createdAt).toLocaleDateString("ko-KR")}</span></span><button className="button button--small" onClick={() => void remove(passkey)} disabled={busy} aria-label={`${passkey.name} Passkey 삭제`}><Trash2 size={12} />삭제</button></li>)}</ul> : <p className="passkey-empty">등록된 전원 Passkey가 없습니다.</p>}
    <form className="passkey-form" onSubmit={(event) => void enroll(event)}>
      <label className="passkey-field">이름<input className="passkey-input" value={name} onChange={(event) => setName(event.target.value)} maxLength={40} autoComplete="off" /></label>
      {status.bootstrapRequired && <label className="passkey-field">부트스트랩 토큰<input className="passkey-input" type="password" value={bootstrapToken} onChange={(event) => setBootstrapToken(event.target.value)} autoComplete="off" /></label>}
      {error && <p className="inline-error" role="alert">{error}</p>}
      <button className="button button--primary" type="submit" disabled={busy}>{busy ? <LoaderCircle className="spin" size={14} /> : <KeyRound size={14} />}{busy ? "확인 중…" : "Passkey 등록"}</button>
    </form>
  </section>;
}

async function reauthenticate(operation: "register_passkey" | "delete_passkey" | "power_on" | "power_off", target?: string) {
  if (!window.PublicKeyCredential) throw new Error("이 브라우저는 WebAuthn을 지원하지 않습니다.");
  const challenge = await beginPowerReauth({ operation, target });
  const credential = await startAuthentication({ optionsJSON: challenge.options as PublicKeyCredentialRequestOptionsJSON });
  return finishPowerReauth({ challengeId: challenge.challengeId, credential });
}

function PowerDialog({ action, deviceId, onClose }: { action: "power_on" | "power_off"; deviceId: string; onClose: () => void }) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const queryClient = useQueryClient();
  const toast = useToast();
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const label = action === "power_on" ? "전원 켜기" : "전원 끄기";

  useEffect(() => {
    cancelRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !pending) onClose();
      if (event.key !== "Tab") return;
      const dialog = document.querySelector<HTMLElement>("[data-power-dialog]");
      const focusable = dialog?.querySelectorAll<HTMLElement>("button:not(:disabled)");
      if (!focusable?.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose, pending]);

  async function confirm() {
    if (pending) return;
    setPending(true);
    setError("");
    try {
      const grant = await reauthenticate(action);
      const result = await queuePowerCommand({ action, reauthGrant: grant.grant });
      await queryClient.invalidateQueries({ queryKey: ["power-status"] });
      toast("전원 명령 전달", `${deviceId} · ${result.command.id.slice(0, 8)}`, "success");
      onClose();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "전원 명령에 실패했습니다.");
      setPending(false);
    }
  }

  return <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && !pending && onClose()}>
    <section className="action-dialog" role="dialog" aria-modal="true" aria-labelledby="power-action-title" data-power-dialog>
      <div className="action-dialog__top"><span className="action-dialog__icon"><Power size={19} aria-hidden="true" /></span><button className="icon-button" onClick={onClose} disabled={pending} aria-label="창 닫기"><X size={18} /></button></div>
      <h2 id="power-action-title">{label} 확인</h2>
      <p className="muted-copy">ESP32는 메인보드 전원 버튼을 짧게 누릅니다. 명령은 한 번만 전달되고 {30}초 안에 사라집니다.</p>
      <dl className="action-target"><div><dt>작업</dt><dd>{label}</dd></div><div><dt>장치</dt><dd className="mono-text">{deviceId}</dd></div></dl>
      <div className="reauth-notice">실행 전 이 동작에만 쓰는 Passkey 재인증이 필요합니다. 길게 눌러 강제 종료하지 않습니다.</div>
      {error && <p className="inline-error" role="alert">{error}</p>}
      <div className="action-dialog__buttons">
        <button ref={cancelRef} className="button button--secondary" onClick={onClose} disabled={pending}>취소</button>
        <button className="button button--primary" type="button" onClick={() => void confirm()} disabled={pending}>{pending ? <LoaderCircle className="spin" size={16} /> : <KeyRound size={16} />}{pending ? "재인증 및 전달 중…" : "Passkey 확인 후 전달"}</button>
      </div>
    </section>
  </div>;
}
