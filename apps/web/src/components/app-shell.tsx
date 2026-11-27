"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ChevronRight, Command, HardDrive, Moon, Search, Sun, X } from "lucide-react";
import { navGroups, navItems, type NavItem } from "@/lib/resources";
import { isPcOffline } from "@/lib/api";
import { useOverviewQuery } from "@/lib/queries";

function ItemLink({ item, onNavigate }: { item: NavItem; onNavigate?: () => void }) {
  const pathname = usePathname();
  const href = item.key ? `/${item.key}` : "/";
  const active = pathname === href;
  const Icon = item.icon;
  return (
    <Link className="nav__link" href={href} aria-current={active ? "page" : undefined} onClick={onNavigate}>
      <Icon size={15} aria-hidden="true" /><span>{item.label}</span>
    </Link>
  );
}

function NavGroups({ onNavigate }: { onNavigate?: () => void }) {
  return <nav className="nav" aria-label="주 메뉴">
    {navGroups.map((group) => <div className="nav__group" key={group.label}>
      <div className="nav__label">{group.label}</div>
      {group.items.map((item) => <ItemLink key={item.key} item={item} onNavigate={onNavigate} />)}
    </div>)}
  </nav>;
}

function trapTab(event: ReactKeyboardEvent<HTMLElement>) {
  if (event.key !== "Tab") return;
  const elements = event.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled)');
  if (!elements.length) { event.preventDefault(); return; }
  const first = elements[0];
  const last = elements[elements.length - 1];
  if (!event.currentTarget.contains(document.activeElement)) { event.preventDefault(); first.focus(); }
  else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { data, isPending, isError, error } = useOverviewQuery();
  const [searchOpen, setSearchOpen] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);
  const [search, setSearch] = useState("");
  const searchButtonRef = useRef<HTMLButtonElement>(null);
  const searchDialogRef = useRef<HTMLElement>(null);
  const moreButtonRef = useRef<HTMLButtonElement>(null);
  const moreDialogRef = useRef<HTMLElement>(null);
  const current = navItems.find((item) => (item.key ? `/${item.key}` : "/") === pathname);
  const filtered = useMemo(() => navItems.filter((item) => `${item.label} ${item.subtitle}`.toLowerCase().includes(search.toLowerCase())), [search]);
  const quickItems = [
    navItems.find((item) => item.key === ""),
    navItems.find((item) => item.key === "services"),
    navItems.find((item) => item.key === "containers"),
    navItems.find((item) => item.key === "notifications"),
  ].filter((item): item is NavItem => item !== undefined).map((item) => item.key === "containers" ? { ...item, label: "Docker" } : item);
  const isMock = data?.mode === "mock";
  const pcOffline = isError && isPcOffline(error);
  const connectionLabel = isPending ? "API 연결 확인 중" : pcOffline ? "PC 꺼짐" : isError ? "관리 API 응답 없음" : !data ? "API 연결 확인 중" : isMock ? "DEMO 모드" : data.status === "connected" ? "Live 연결" : data.status === "unavailable" ? "에이전트 재연결 중" : "호스트 연결 대기";
  const closeSearch = useCallback(() => { setSearch(""); setSearchOpen(false); searchButtonRef.current?.focus(); }, []);
  const closeMore = useCallback(() => { setMoreOpen(false); moreButtonRef.current?.focus(); }, []);

  useEffect(() => {
    try {
      const savedTheme = window.localStorage.getItem("homeserver-admin-theme");
      if (savedTheme === "light" || savedTheme === "dark") {
        document.documentElement.dataset.theme = savedTheme;
      }
    } catch { /* Theme still works when browser storage is unavailable. */ }
  }, []);

  const toggleTheme = () => {
    const nextTheme = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = nextTheme;
    try { window.localStorage.setItem("homeserver-admin-theme", nextTheme); } catch { /* Keep the current session usable. */ }
  };

  useEffect(() => {
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        if (searchOpen) closeSearch();
        else { setMoreOpen(false); setSearchOpen(true); }
      }
      if (event.key === "Escape") {
        if (searchOpen) closeSearch();
        else if (moreOpen) closeMore();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [closeMore, closeSearch, moreOpen, searchOpen]);

  useEffect(() => {
    if (searchOpen) searchDialogRef.current?.querySelector<HTMLInputElement>("input")?.focus();
    if (moreOpen) moreDialogRef.current?.querySelector<HTMLElement>("button:not(:disabled), a[href]")?.focus();
  }, [moreOpen, searchOpen]);

  const choose = (item: NavItem) => {
    router.push(item.key ? `/${item.key}` : "/");
    setSearch("");
    setSearchOpen(false);
    searchButtonRef.current?.focus();
  };

  return <div className="app-shell">
    <aside className="sidebar" aria-label="사이드바">
      <Link className="brand" href="/">
        <span className="brand__mark"><HardDrive size={17} aria-hidden="true" /></span>
        <span><span className="brand__name">HomeServer</span><span className="brand__meta">ADMIN CONSOLE</span></span>
      </Link>
      <NavGroups />
      <div className="sidebar__footer">
        <div className="connection-mini">
          <i className="connection-mini__dot" aria-hidden="true" />
          <div><div className="connection-mini__title">{connectionLabel}</div>
            <div className="connection-mini__detail">{pcOffline ? "전원 메뉴는 사용할 수 있습니다" : data?.serverName ?? "연결 상태 확인 중"}</div></div>
        </div>
      </div>
    </aside>

    <main className="app-shell__main">
      <header className="topbar">
        <div className="breadcrumbs"><span>HomeServer Admin</span><ChevronRight size={13} aria-hidden="true" /><strong>{current?.label ?? "페이지"}</strong></div>
        <div className="topbar__actions">
          <div className="status-pill"><i className="status-pill__dot" aria-hidden="true" />{connectionLabel}</div>
          <button className="icon-button theme-toggle" onClick={toggleTheme} aria-label="라이트/다크 모드 전환">
            <Sun className="theme-toggle__light" size={15} aria-hidden="true" /><Moon className="theme-toggle__dark" size={15} aria-hidden="true" />
          </button>
          <button ref={searchButtonRef} className="search-button" onClick={() => setSearchOpen(true)} aria-label="검색 ⌘ K"><Search size={14} /><span>검색</span><kbd className="kbd" aria-hidden="true">⌘ K</kbd></button>
        </div>
      </header>
      {children}
    </main>

    <nav className="mobile-nav" aria-label="빠른 메뉴">
      {quickItems.map((item) => { const Icon = item.icon; const href = item.key ? `/${item.key}` : "/"; return <Link className="mobile-nav__item" key={item.key} href={href} aria-current={pathname === href ? "page" : undefined}><Icon size={17} /><span>{item.label}</span></Link>; })}
      <button ref={moreButtonRef} className="mobile-nav__item" onClick={() => setMoreOpen(true)} aria-expanded={moreOpen}><Command size={17} /><span>더보기</span></button>
    </nav>

    {moreOpen && <div className="more-sheet" onMouseDown={(event) => event.target === event.currentTarget && closeMore()}>
      <section ref={moreDialogRef} className="more-sheet__panel" role="dialog" aria-modal="true" aria-label="전체 메뉴" onKeyDown={trapTab}>
        <div className="more-sheet__head"><span>전체 메뉴</span><button className="icon-button" aria-label="닫기" onClick={closeMore}><X size={17} /></button></div>
        <NavGroups onNavigate={closeMore} />
      </section>
    </div>}

    {searchOpen && <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && closeSearch()}>
      <section ref={searchDialogRef} className="command-dialog" role="dialog" aria-modal="true" aria-label="페이지 검색" onKeyDown={trapTab}>
        <div className="command-input-wrap"><Search size={17} /><input aria-label="페이지 이름으로 검색" className="command-input" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="페이지 이름으로 검색" onKeyDown={(event) => { if (event.key === "Enter" && filtered[0]) choose(filtered[0]); }} /><kbd className="kbd">ESC</kbd></div>
        <div className="command-list">{filtered.length ? filtered.map((item) => { const Icon = item.icon; return <button className="command-item" key={item.key} onClick={() => choose(item)}><Icon size={15} /><span>{item.label}</span><span className="muted-copy">{item.subtitle}</span></button>; }) : <div className="command-empty">검색 결과가 없습니다.</div>}</div>
      </section>
    </div>}
  </div>;
}
