import type { Metadata } from "next";
import { QueryProvider } from "@/components/query-provider";
import { ToastProvider } from "@/components/toast-provider";
import { AppShell } from "@/components/app-shell";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "HomeServer Admin", template: "%s | HomeServer Admin" },
  description: "개인 서버 운영을 위한 관리 콘솔",
  manifest: "/manifest.webmanifest",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="ko">
      <body>
        <QueryProvider><ToastProvider><AppShell>{children}</AppShell></ToastProvider></QueryProvider>
      </body>
    </html>
  );
}
