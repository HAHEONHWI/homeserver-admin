# HomeServer Admin Design System

## 1. Atmosphere & Identity

A dark, information-dense server control room. Preserve the supplied Claude design's quiet surfaces, blue actions, Korean labels, and visible connection states. The source design is the visual contract; no substitute mockup or decorative treatment.

Reference sources: `HomeServer Admin.dc.html`, `HomeServer Overview 시안.dc.html`, `TimeChart.dc.html`, and `support.js` inside `프로젝트 시작 전 확인사항.zip`. The root `HomeServer Admin.html` is a bundled preview, not production source.

## 2. Color

| Role | Token | Dark | Light | Usage |
|---|---|---|---|---|
| App background | `--color-bg` | `#0B0E14` | `#F6F8FB` | Main canvas |
| Sidebar | `--color-sidebar` | `#090C11` | `#FFFFFF` | Fixed navigation |
| Top bar | `--color-topbar-bg` | `#0B0E14EF` | `#F6F8FBEF` | Sticky header |
| Mobile navigation | `--color-mobile-nav-bg` | `#090C11F5` | `#FFFFFFF5` | Fixed mobile navigation |
| Surface 1 | `--color-surface-1` | `#11151C` | `#FFFFFF` | Main panels |
| Surface 2 | `--color-surface-2` | `#171C25` | `#F2F5F9` | Controls, raised rows |
| Surface 3 | `--color-surface-3` | `#1F2530` | `#E9EEF5` | Hover and nested surfaces |
| Text | `--color-text` | `#E7EAEF` | `#1D2735` | Primary content |
| Text secondary | `--color-text-2` | `#A3ACBA` | `#475467` | Supporting content |
| Text muted | `--color-text-3` | `#7D8797` | `#667085` | Metadata and disabled content |
| Rule | `--color-line` | `#1F2631` | `#E5E9F0` | Dividers |
| Rule strong | `--color-line-2` | `#2B3340` | `#CBD3DF` | Input and panel boundaries |
| Accent | `--color-accent` | `#4C8DFF` | `#2563EB` | Links, focus, selected actions |
| Accent solid | `--color-accent-solid` | `#2563EB` | `#2563EB` | Primary buttons |
| Accent hover | `--color-accent-hover` | `#8DB6FF` | `#1D4ED8` | Hover text |
| Success | `--color-success` | `#3DD68C` | `#16804A` | Healthy states |
| Warning | `--color-warning` | `#F5B544` | `#9A5B00` | Degraded states |
| Error | `--color-error` | `#FF6B6B` | `#CF3434` | Failed states |
| Error text | `--color-error-text` | `#FF7A7A` | `#B42318` | Error copy |
| Violet | `--color-violet` | `#A78BFA` | `#7C3AED` | Secondary chart series |
| Disabled | `--color-disabled` | `#4B5565` | `#98A2B3` | Disabled controls |

Dark is the default theme; the light values apply under `:root[data-theme="light"]`. Use the original low-alpha status fills derived from the matching status token. Add no new palette colors without updating this table.

## 3. Typography

- Sans: `Pretendard Variable`, `Pretendard`, system sans-serif.
- Mono: `JetBrains Mono`, monospace; use for IDs, versions, timestamps, and logs.
- Sizes follow source: 11, 12, 12.5, 13, 14, 15, 16, 20, and 26px. Body copy uses 14px; smaller sizes are for labels and metadata.
- Weights: 400, 500, 600, 650. Page titles use 20–26px; panel titles use 14–16px.

## 4. Spacing & Layout

- Source spacing scale: 2, 4, 6, 8, 10, 12, 14, 16, 20, and 24px. Use CSS tokens for repeated intent.
- Source radii: 6, 8, 10, and 12px; larger dialogs use 16px.
- Surfaces use tonal steps with neutral 1px rules. Overlays may use shadows; cards do not get accent outlines or decorative edge bars.
- Desktop keeps navigation fixed while `.app-shell__main` scrolls. Mobile replaces the sidebar with the source design's bottom navigation. The shell is bounded by `100dvh`.
- Layout: All management routes - keep navigation stable while content changes and grows -> fixed-sidenav-shell (https://github.com/changeroa/StyleGallery/blob/main/patterns/viewport-shell/fixed-sidenav-shell.md); scroll owner: `.app-shell__main`; anti-patterns: document-level competing scroll, unlabeled nested scrollbars, visual order that differs from keyboard order.
- Required viewport checks: 320, 390, 430, 768, 1280, 1440, and 1920px. At mobile widths, primary content has no horizontal overflow.

## 5. Components

### App shell and navigation
- **Structure**: fixed sidebar, header, main landmark, mobile bottom navigation.
- **States**: active route, hover, focus-visible, collapsed mobile navigation.
- **Accessibility**: semantic links, visible focus, source order follows reading order.
- **Motion**: short opacity/transform transitions; reduced motion uses cross-fade.

### Metric panel and chart
- **Structure**: label, current value, unit/change, optional chart.
- **States**: loading, live, demo, stale, unavailable, error.
- **Accessibility**: values have text equivalents; charts have a summary.

### Service row and status
- **Structure**: service name, state, last check, available action.
- **States**: healthy, degraded, stopped, unavailable, pending.
- **Accessibility**: status uses text and icon, not color alone.

### Table, log viewer, and filters
- **Structure**: labeled controls, result count, rows, empty/error state.
- **States**: loading, populated, empty, disconnected, filtered, paused stream.
- **Accessibility**: keyboard-operable sort/filter controls; logs use a labeled region.

### Modal, drawer, toast, and reauthentication
- **Structure**: named dialog, clear target/action, cancel and confirm controls.
- **States**: open, busy, success, failure, expired reauthentication.
- **Accessibility**: focus stays inside dialogs, Escape closes non-destructive overlays, destructive actions are never the Enter default.
- **Security**: real sensitive actions remain disabled until Live authentication and the restricted agent are configured.

### Screen briefs

#### Overview
- Primary action: refresh server status.
- Priorities: server/service health; CPU, RAM, storage, and network; recent deployment, alert, and management activity.
- Required content: core load, uptime, Docker state, last refresh, service health, latest deployment, alert, and action.
- Left out: duplicate summary tiles and static promotional badges.

#### Management routes
- Primary action: inspect the selected resource or connection state.
- Priorities: route health; resource list and key values; supported next action.
- Required content: System, Docker, Deployments, AI & Automation, Network & Domains, Mail, Databases, Storage, Monitoring & Alerts, Security & Audit, and Settings.
- Unconfigured integrations render as disconnected/unavailable, never as successful live data.

## 6. Motion & Interaction

- Micro feedback: 100–150ms ease-out. Panel/dialog transition: 200–300ms ease-in-out.
- Animate `transform` and `opacity`; controls respond on the same frame. Respect `prefers-reduced-motion` with a cross-fade.
- Async actions immediately disable the initiating control and show progress only while work is active. Report failure beside the affected resource.
- Search opens with ⌘K/Ctrl+K; overlays close with Escape; no action relies on hover.

## 7. Depth & Surface

- Strategy: mixed. Tonal surfaces and neutral hairlines define panels; shadows are reserved for modals and drawers.
- Radius scale: 6px small controls, 8px buttons, 10px panels, 12px large panels, 16px dialogs.
- No decorative accent border, one-sided color stripe, or static badge.

## 8. Accessibility Constraints & Accepted Debt

- Target WCAG 2.2 AA: body text contrast 4.5:1, large text 3:1, visible keyboard focus, semantic controls, reduced motion, and status labels that do not rely on color.
- Accepted debt: browser-only visual comparison to the bundled `file://` reference is unavailable because the browser policy rejects local-file URLs. Continue source-based comparison; do not bypass that policy.
