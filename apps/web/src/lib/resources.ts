import {
  Activity, Archive, Bell, Bot, Boxes, Database, Globe2, HardDrive, Layers, Package,
  LayoutDashboard, Mail, Power, Settings2, Shield, Server,
  type LucideIcon,
} from "lucide-react";

export type NavItem = { key: string; label: string; icon: LucideIcon; subtitle: string };
export type NavGroup = { label: string; items: NavItem[] };

export const navGroups: NavGroup[] = [
  { label: "Overview", items: [{ key: "", label: "개요", icon: LayoutDashboard, subtitle: "서버 상태와 최근 운영 기록" }] },
  { label: "전원", items: [{ key: "power", label: "전원", icon: Power, subtitle: "원격 전원과 PC 연결 상태" }] },
  { label: "관리", items: [
    { key: "services", label: "서비스", icon: Server, subtitle: "서비스 상태와 연결 정보" },
    { key: "notifications", label: "알림", icon: Bell, subtitle: "최근 알림과 운영 이벤트" },
    { key: "system", label: "시스템", icon: Activity, subtitle: "호스트 상태와 자원 사용량" },
    { key: "automation", label: "AI · 자동화", icon: Bot, subtitle: "자동화 연결 상태와 실행 기록" },
  ] },
  { label: "인프라", items: [
    { key: "domains", label: "도메인 · DNS", icon: Globe2, subtitle: "도메인과 DNS 제공자 연결" },
    { key: "mail", label: "메일", icon: Mail, subtitle: "메일 서비스 연결과 계정" },
    { key: "database", label: "데이터베이스", icon: Database, subtitle: "데이터베이스와 백업" },
    { key: "storage", label: "스토리지", icon: HardDrive, subtitle: "디스크와 스토리지 연결" },
    { key: "monitoring", label: "모니터링 · 알림", icon: Activity, subtitle: "모니터링과 알림 대상" },
  ] },
  { label: "운영", items: [
    { key: "security", label: "보안 · 감사", icon: Shield, subtitle: "인증 상태와 감사 이벤트" },
    { key: "settings", label: "설정", icon: Settings2, subtitle: "연결 및 애플리케이션 설정" },
    { key: "containers", label: "컨테이너", icon: Boxes, subtitle: "컨테이너 런타임 연결" },
    { key: "images", label: "이미지", icon: Package, subtitle: "Docker 이미지와 태그" },
    { key: "stacks", label: "Compose 스택", icon: Layers, subtitle: "배포된 Docker Compose 스택" },
    { key: "deployments", label: "배포", icon: Archive, subtitle: "배포 공급자와 작업 상태" },
  ] },
];

export const navItems = navGroups.flatMap((group) => group.items);
export const resourceItems = navItems.filter((item) => item.key !== "");
export const findNavItem = (key: string) => navItems.find((item) => item.key === key);
