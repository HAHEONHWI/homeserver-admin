"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, LoaderCircle, Plus, Trash2 } from "lucide-react";
import {
  beginPasskeyReauth,
  beginPasskeyRegistration,
  finishPasskeyReauth,
  finishPasskeyRegistration,
  getPasskeyStatus,
  removePasskey,
} from "@/lib/api";
import { useToast } from "@/components/toast-provider";
import type { PasskeyItem } from "@/lib/contracts";

export function PasskeyManager() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const status = useQuery({ queryKey: ["passkeys"], queryFn: ({ signal }) => getPasskeyStatus(signal) });
  const [name, setName] = useState("");
  const [bootstrapToken, setBootstrapToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [busyId, setBusyId] = useState("");
  const [error, setError] = useState("");
  const [pendingDelete, setPendingDelete] = useState<PasskeyItem | null>(null);
  const deleteDialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    if (pendingDelete && deleteDialog.current && !deleteDialog.current.open) {
      deleteDialog.current.showModal();
    }
  }, [pendingDelete]);

  async function reauthenticate(operation: "register_passkey" | "delete_passkey", target: string) {
    if (!window.PublicKeyCredential) throw new Error("이 브라우저는 WebAuthn을 지원하지 않습니다.");
    const challenge = await beginPasskeyReauth({ operation, target });
    const credential = await startAuthentication({
      optionsJSON: challenge.options as unknown as PublicKeyCredentialRequestOptionsJSON,
    });
    return finishPasskeyReauth({ challengeId: challenge.challengeId, credential });
  }

  async function addPasskey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!status.data || busy) return;
    setBusy(true);
    setError("");
    const token = bootstrapToken;
    setBootstrapToken("");
    try {
      if (!window.PublicKeyCredential) throw new Error("이 브라우저는 WebAuthn을 지원하지 않습니다.");
      const grant = status.data.bootstrapRequired
        ? undefined
        : (await reauthenticate("register_passkey", "account")).grant;
      const challenge = await beginPasskeyRegistration({
        name: name.trim() || "내 기기",
        ...(status.data.bootstrapRequired ? { bootstrapToken: token } : { reauthGrant: grant }),
      });
      const credential = await startRegistration({
        optionsJSON: challenge.options as unknown as PublicKeyCredentialCreationOptionsJSON,
      });
      await finishPasskeyRegistration({ challengeId: challenge.challengeId, credential });
      setName("");
      await queryClient.invalidateQueries({ queryKey: ["passkeys"] });
      toast("Passkey 등록 완료", "이 계정에 새 Passkey를 추가했습니다.", "success");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Passkey 등록에 실패했습니다.");
    } finally {
      setBusy(false);
    }
  }

  async function deletePasskey(id: string, passkeyName: string) {
    if (busy) return;
    setBusy(true);
    setBusyId(id);
    setError("");
    try {
      const grant = await reauthenticate("delete_passkey", id);
      await removePasskey({ credentialId: id, reauthGrant: grant.grant });
      await queryClient.invalidateQueries({ queryKey: ["passkeys"] });
      toast("Passkey 삭제 완료", `${passkeyName} Passkey를 삭제했습니다.`, "success");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Passkey 삭제에 실패했습니다.");
    } finally {
      setBusy(false);
      setBusyId("");
    }
  }

  return (
    <section className="panel passkey-panel" aria-labelledby="passkey-title" aria-busy={busy || status.isFetching}>
      <div className="panel__head">
        <div><h2 className="panel__title" id="passkey-title">Passkey</h2><p className="panel__subtitle">이 계정의 본인 확인과 보안 설정에 사용합니다.</p></div>
        <KeyRound size={16} className="metric-card__icon" aria-hidden="true" />
      </div>
      {status.isPending ? <p className="empty-inline" role="status">Passkey 상태를 불러오는 중입니다.</p> : status.isError ? <div className="passkey-state" role="alert"><span>{status.error.message}</span><button className="button button--small" onClick={() => void status.refetch()}>다시 시도</button></div> : (
        <>
          {status.data.passkeys.length ? <ul className="passkey-list">
            {status.data.passkeys.map((passkey) => <li className="passkey-row" key={passkey.id}>
              <div className="passkey-row__identity"><strong>{passkey.name}</strong><span>등록 {new Date(passkey.createdAt).toLocaleString("ko-KR")}</span></div>
              <button className="button button--small button--secondary" onClick={() => setPendingDelete(passkey)} disabled={busy || status.data.passkeys.length < 2} aria-label={`${passkey.name} Passkey 삭제`} title={status.data.passkeys.length < 2 ? "최소 하나의 Passkey는 유지해야 합니다." : undefined}>
                {busyId === passkey.id ? <LoaderCircle size={13} className="spin" /> : <Trash2 size={13} />}삭제
              </button>
            </li>)}
          </ul> : <p className="passkey-empty">등록된 Passkey가 없습니다.</p>}
          {status.data.bootstrapRequired && <p className="passkey-help">첫 등록에는 서버 관리자가 발급한 <code>WEBAUTHN_BOOTSTRAP_TOKEN</code>이 필요합니다.</p>}
          {!status.data.bootstrapRequired && <p className="passkey-help">추가·삭제할 때마다 기존 Passkey의 생체 인식 또는 기기 PIN으로 재인증합니다.</p>}
          <form className="passkey-form" onSubmit={addPasskey}>
            <label className="passkey-field"><span>Passkey 이름</span><input className="passkey-input" value={name} maxLength={64} onChange={(event) => setName(event.target.value)} placeholder="예: 개인 MacBook" autoComplete="off" required /></label>
            {status.data.bootstrapRequired && <label className="passkey-field"><span>초기 등록 토큰 · 64자리 소문자 16진수</span><input className="passkey-input" type="password" value={bootstrapToken} minLength={64} maxLength={64} pattern="[0-9a-f]{64}" onChange={(event) => setBootstrapToken(event.target.value)} autoComplete="off" spellCheck={false} required /></label>}
            {error && <p className="inline-error" role="alert">{error}</p>}
            <div><button className="button button--primary" type="submit" disabled={busy || !name.trim() || (status.data.bootstrapRequired && !bootstrapToken)}>
              {busy ? <LoaderCircle size={15} className="spin" /> : <Plus size={15} />}{busy ? "확인 중…" : "Passkey 추가"}
            </button></div>
          </form>
        </>
      )}
      <dialog ref={deleteDialog} className="action-dialog confirm-dialog" aria-labelledby="passkey-delete-title" onClose={() => setPendingDelete(null)}>
        <span className="action-dialog__icon"><Trash2 size={18} aria-hidden="true" /></span>
        <h2 id="passkey-delete-title">Passkey 삭제</h2>
        <p className="muted-copy">삭제할 Passkey를 확인하세요. 계속하려면 기존 Passkey로 본인 확인해야 합니다.</p>
        <dl className="action-target"><div><dt>대상</dt><dd>{pendingDelete?.name}</dd></div></dl>
        <div className="action-dialog__buttons">
          <button className="button button--secondary" autoFocus onClick={() => deleteDialog.current?.close()}>취소</button>
          <button className="button button--primary" onClick={() => {
            if (!pendingDelete) return;
            const item = pendingDelete;
            deleteDialog.current?.close();
            void deletePasskey(item.id, item.name);
          }}>삭제하고 재인증</button>
        </div>
      </dialog>
    </section>
  );
}
