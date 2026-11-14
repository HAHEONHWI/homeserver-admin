"use client";

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";

type ToastMessage = { id: number; title: string; detail: string; tone: "success" | "error" | "info" };
type ToastContextValue = (title: string, detail: string, tone?: ToastMessage["tone"]) => void;

const ToastContext = createContext<ToastContextValue>(() => undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<ToastMessage | null>(null);
  const notify = useCallback<ToastContextValue>((title, detail, tone = "info") => {
    setToast({ id: Date.now(), title, detail, tone });
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 4_000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  return (
    <ToastContext.Provider value={notify}>
      {children}
      {toast && (
        <div key={toast.id} className={`toast toast--${toast.tone}`} role="status" aria-live="polite">
          <span className="toast__title">{toast.title}</span>
          {toast.detail && <span className="toast__detail">{toast.detail}</span>}
          <button className="icon-button toast__close" onClick={() => setToast(null)} aria-label="알림 닫기">×</button>
        </div>
      )}
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);

