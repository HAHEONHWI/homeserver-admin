import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("automation page shows bounded n8n execution metadata without controls", async ({ page }) => {
  await page.route("**/api/v1/resources/automation", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      key: "automation", mode: "live", status: "connected", message: "n8n readiness · 최근 실행 이력",
      updatedAt: "2026-11-10T03:00:02Z", metrics: [],
      columns: ["연동", "상태", "확인 결과", "갱신"], actions: [],
      rows: [
        { id: "n8n", name: "n8n", status: "정상", detail: "HTTP 200 · 준비 상태", updatedAt: "2026-11-10T03:00:02Z" },
        { id: "n8n-history", name: "n8n 실행 이력", status: "최근 1개", detail: "메타데이터만 조회 · 실행 payload 제외", updatedAt: "2026-11-10T03:00:02Z" },
        { id: "n8n-execution:42", name: "n8n workflow workflow-7", status: "실패", detail: "실행 42 · 실행 상태 메타데이터", updatedAt: "2026-11-10T03:00:02Z" },
      ],
    }),
  }));
  await page.goto("/automation");
  const table = page.getByRole("table");
  await expect(table).toContainText("n8n 실행 이력");
  await expect(table).toContainText("workflow-7");
  await expect(table).toContainText("실행 42");
  await expect(table).toContainText("실패");
  await expect(page.getByRole("button", { name: /재시작|실행/ })).toHaveCount(0);
});

test("monitoring page shows live Netdata and Scrutiny status with unavailable Uptime Kuma", async ({ page }) => {
  await page.route("**/api/v1/resources/monitoring", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      key: "monitoring", mode: "live", status: "partial",
      message: "Netdata 주의 · Scrutiny 정상 · Uptime Kuma 미연결",
      updatedAt: "2026-11-10T03:00:00Z",
      metrics: [
        { label: "연동", value: "2/3", detail: "Netdata · Uptime Kuma · Scrutiny" },
        { label: "활성 경보", value: "1", detail: "WARNING · CRITICAL" },
        { label: "디스크", value: "1", detail: "Scrutiny 장치 요약" },
        { label: "디스크 이상", value: "0", detail: "Scrutiny S.M.A.R.T 상태" },
      ],
      columns: ["모니터", "상태", "설명", "갱신"], actions: [],
      rows: [
        { id: "netdata", name: "Netdata Agent", status: "주의", detail: "현재 WARNING 1 · CRITICAL 0 · 최근 경보 최대 100개", updatedAt: "2026-11-10T03:00:00Z" },
        { id: "uptime-kuma", name: "Uptime Kuma", status: "미연결", detail: "공식 지원 읽기 API adapter 없음", updatedAt: "2026-11-10T03:00:00Z" },
        { id: "scrutiny", name: "Scrutiny", status: "정상", detail: "1개 장치 · 비정상 0개", updatedAt: "2026-11-10T03:00:00Z" },
        { id: "scrutiny:0", name: "Scrutiny · OS SSD", status: "정상", detail: "Samsung 980 PRO · 1000.0 GB · 38°C · 800시간", updatedAt: "2026-11-10T02:50:00Z" },
        { id: "netdata-alert:0", name: "cpu_usage", status: "WARNING", detail: "system.cpu · 78 %", updatedAt: "2026-11-10T03:00:00Z" },
      ],
    }),
  }));
  await page.goto("/monitoring");
  const table = page.getByRole("table");
  await expect(table).toContainText("Netdata Agent");
  await expect(table).toContainText("cpu_usage");
  await expect(table).toContainText("Uptime Kuma");
  await expect(page.getByText("2/3")).toBeVisible();
  await expect(table).toContainText("38°C");
  await expect(page.getByRole("button", { name: /재시작|실행|변경/ })).toHaveCount(0);
});

test("overview reflects demo data and a simulation is audited", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "개요" })).toBeVisible();
  await expect(page.getByText("DEMO 모드", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "서비스 상태" })).toBeVisible();

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/containers");
  await page.getByRole("button", { name: "web", exact: true }).click();
  const logsStream = page.waitForRequest((request) => request.url().includes("/logs/stream"));
  await page.getByRole("button", { name: "실시간 로그" }).click();
  await logsStream;
  await expect(page.getByRole("dialog")).toContainText("DEMO · 컨테이너가 시작되었습니다.");
  await page.screenshot({ path: "test-results/container-logs-390.png", fullPage: true });
  await page.getByRole("button", { name: "컨테이너 상세 닫기" }).click();
  await page.getByRole("button", { name: "재시작" }).click();
  await expect(page.getByRole("dialog")).toContainText("실제 서버 명령은 호출하지 않습니다");
  await page.getByRole("button", { name: "모의 작업 실행" }).click();
  await expect(page.getByText("DEMO 작업 완료")).toBeVisible();

  await page.goto("/security");
  await expect(page.getByText("simulated").first()).toBeVisible();
});

test("Docker resources provide searchable containers and a bounded detail drawer", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/containers");
  await expect(page.getByRole("navigation", { name: "Docker 리소스" }).getByRole("link", { name: "컨테이너" })).toHaveAttribute("aria-current", "page");
  await expect(page.getByRole("button", { name: "web", exact: true })).toBeVisible();
  await page.getByRole("textbox", { name: "컨테이너 검색" }).fill("not-found");
  await expect(page.getByText("검색 또는 상태 조건에 맞는 컨테이너가 없습니다.")).toBeVisible();
  await page.getByRole("textbox", { name: "컨테이너 검색" }).fill("web");

  const stats = page.waitForResponse((response) => response.url().endsWith("/api/v1/containers/container/stats"));
  await page.getByRole("button", { name: "web", exact: true }).click();
  expect((await stats).status()).toBe(200);
  const drawer = page.getByRole("dialog", { name: "web" });
  await expect(drawer).toContainText("DEMO · 실제 Docker 컨테이너가 아닙니다.");
  await expect(drawer).toContainText("3.2%");

  const logStream = page.waitForRequest((request) => request.url().includes("/containers/container/logs/stream"));
  await drawer.getByRole("button", { name: "실시간 로그" }).click();
  await logStream;
  await expect(drawer.getByRole("button", { name: "로그 일시정지" })).toBeVisible();
  await drawer.getByRole("button", { name: "로그 일시정지" }).click();
  await expect(drawer.getByRole("button", { name: "로그 재개" })).toBeVisible();
  await drawer.getByLabel("로그 수준 필터").selectOption("error");
  await expect(drawer.getByText("표시할 로그가 없습니다.")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(drawer).not.toBeVisible();
  await expect(page.getByRole("button", { name: "web", exact: true })).toBeFocused();

  const directLogStream = page.waitForRequest((request) => request.url().includes("/containers/container/logs/stream"));
  await page.getByRole("button", { name: "로그 보기" }).click();
  await directLogStream;
  await expect(page.getByRole("button", { name: "실시간 로그" })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "컨테이너 상세 닫기" }).click();
});

test("live container trend chart uses successive API samples", async ({ page }) => {
  const id = "a".repeat(64);
  await page.route("**/api/v1/resources/containers", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ key: "containers", mode: "live", status: "connected", message: "Portainer 상태 조회", updatedAt: "2026-11-09T00:00:00Z", metrics: [], columns: ["컨테이너", "상태", "이미지 · 포트", "갱신"], rows: [{ id, name: "web", status: "running · Up 1 minute", detail: "nginx:stable · 80/tcp", updatedAt: "2026-11-09T00:00:00Z" }], actions: [] }),
  }));
  let sample = 0;
  await page.route("**/api/v1/containers/*/stats", (route) => {
    sample += 1;
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ mode: "live", id, status: "connected", cpuPercent: 2 + sample, memoryUsedBytes: 42_000_000, memoryLimitBytes: 256_000_000, memoryPercent: 16 + sample, message: "Portainer Docker stats", updatedAt: `2026-11-09T00:00:0${sample}Z` }),
    });
  });
  await page.goto("/containers");
  const firstSample = page.waitForResponse((response) => response.url().endsWith(`/api/v1/containers/${id}/stats`));
  await page.getByRole("button", { name: "web", exact: true }).click();
  expect((await firstSample).status()).toBe(200);
  await expect(page.getByText("Live 측정값이 2회 이상 수집되면 추이를 표시합니다.")).toBeVisible();
  const nextSample = page.waitForResponse((response) => response.url().endsWith(`/api/v1/containers/${id}/stats`));
  await page.getByRole("button", { name: "통계 새로고침" }).click();
  expect((await nextSample).status()).toBe(200);
  const chart = page.getByRole("img", { name: /최근 2개 Live CPU 및 메모리 측정값/ });
  await expect(chart).toBeVisible();
  const size = await chart.boundingBox();
  if (!size) throw new Error("Trend chart is not laid out");
  await chart.hover({ position: { x: Math.round(size.width * 0.7), y: Math.round(size.height * 0.5) } });
  const tooltip = page.locator(".recharts-tooltip-wrapper");
  await expect(tooltip).toContainText("CPU");
  await expect(tooltip).toContainText("메모리");
});

test("live Docker actions confirm the exact container before Passkey reauthentication", async ({ page }) => {
  const id = "d".repeat(64);
  await page.route("**/api/v1/resources/containers", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      key: "containers", mode: "live", status: "connected", message: "Portainer 상태 조회 · 제한된 컨테이너 제어",
      updatedAt: "2026-11-09T00:00:00Z", metrics: [],
      columns: ["컨테이너", "상태", "이미지 · 포트", "갱신"],
      rows: [{
        id, name: "web-prod", status: "running · Up 1 minute", detail: "nginx:stable · 80/tcp", updatedAt: "2026-11-09T00:00:00Z",
        actions: [{ id: "stop", label: "중지", operation: "stop", target: id, targetLabel: "web-prod", enabled: true, reason: "Passkey 재인증 후 이 작업만 실행합니다." }],
      }],
      actions: [],
    }),
  }));

  await page.goto("/containers");
  await page.getByRole("button", { name: "중지", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "중지 확인" });
  await expect(dialog).toContainText("web-prod");
  await expect(dialog).toContainText(id);
  await expect(dialog.getByRole("button", { name: "Passkey 확인 후 실행" })).toBeEnabled();
  await dialog.getByRole("button", { name: "취소" }).click();
  await expect(dialog).not.toBeVisible();
});

test("Live DNS edits show mail warnings and require review confirmation", async ({ page }) => {
  const id = "f".repeat(32);
  await page.setViewportSize({ width: 320, height: 780 });
  await page.route("**/api/v1/resources/domains", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      key: "domains", mode: "live", status: "connected", message: "Cloudflare DNS 조회",
      updatedAt: "2026-11-09T00:00:00Z", metrics: [], writeEnabled: true,
      columns: ["호스트명", "유형 · Proxy", "값 · TTL", "갱신"], actions: [],
      rows: [{
        id, name: "mail.example.com", status: "MX · DNS only", detail: "mx.example.com · TTL 3600초",
        updatedAt: "2026-11-09T00:00:00Z",
        dnsRecord: { name: "mail.example.com", type: "MX", content: "mx.example.com", ttl: 3600, proxied: false, priority: 10 },
      }],
    }),
  }));
  await page.route("**/api/v1/audit?limit=100", (route) => route.fulfill({
    status: 200, contentType: "application/json", body: "[]",
  }));
  await page.goto("/domains");
  await page.getByRole("button", { name: "편집", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "DNS 레코드 변경 확인" });
  const dialogBounds = await dialog.boundingBox();
  expect(dialogBounds?.width).toBeLessThanOrEqual(320);
  const headingBounds = await dialog.getByRole("heading", { name: "DNS 레코드 변경 확인" }).boundingBox();
  expect(headingBounds?.y).toBeLessThan(180);
  await expect(dialog).toContainText("MX · mail.example.com · mx.example.com · TTL 3600 · priority 10");
  await expect(dialog.getByRole("alert")).toContainText("MX, SPF, DKIM 또는 DMARC");
  await page.screenshot({ path: "test-results/dns-record-dialog-320.png" });
  await dialog.getByRole("textbox", { name: "값" }).fill("mx2.example.com");
  await expect(dialog).toContainText("현재 값");
  await expect(dialog).toContainText("mx2.example.com");
  const execute = dialog.getByRole("button", { name: "Passkey 확인 후 실행" });
  await expect(execute).toBeDisabled();
  await dialog.getByRole("checkbox", { name: "변경 대상과 현재·변경 값을 확인했습니다." }).check();
  await expect(execute).toBeEnabled();
  await dialog.getByRole("button", { name: "취소" }).click();
});

test("DNS audit history restores the prior value through a new confirmation", async ({ page }) => {
  const id = "9".repeat(32);
  const before = { name: "api.example.com", type: "A", content: "192.0.2.4", ttl: 300, proxied: false };
  const after = { ...before, content: "192.0.2.5" };
  await page.route("**/api/v1/resources/domains", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      key: "domains", mode: "live", status: "connected", message: "Cloudflare DNS 조회",
      updatedAt: "2026-11-09T00:00:00Z", metrics: [], writeEnabled: true,
      columns: ["호스트명", "유형 · Proxy", "값 · TTL", "갱신"], actions: [], rows: [],
    }),
  }));
  await page.route("**/api/v1/audit?limit=100", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify([{
      id: "audit-1", actor: "owner@example.com", operation: "dns_update", target: "A api.example.com",
      result: "succeeded", created_at: "2026-11-09T00:00:00Z",
      details: JSON.stringify({ before, after, result: { id, ...after } }),
    }]),
  }));
  await page.goto("/domains");
  const history = page.getByRole("region", { name: "DNS 변경 기록" });
  await expect(history).toContainText("192.0.2.4");
  await expect(history).toContainText("192.0.2.5");
  await expect(history).toContainText("TTL 300");
  await expect(history).toContainText("Proxy 미사용");
  await history.getByRole("button", { name: "이 변경 되돌리기" }).click();
  const dialog = page.getByRole("dialog", { name: "DNS 레코드 변경 확인" });
  await expect(dialog.getByText("현재 값")).toBeVisible();
  await expect(dialog.getByRole("textbox", { name: "값" })).toHaveValue("192.0.2.4");
  await expect(dialog.getByRole("button", { name: "Passkey 확인 후 실행" })).toBeDisabled();
});

test("Mock DNS changes are simulated and recorded with before and after values", async ({ page }) => {
  await page.goto("/domains");
  await page.getByRole("button", { name: "DNS 추가" }).click();
  const dialog = page.getByRole("dialog", { name: "DNS 레코드 추가 확인" });
  await dialog.getByLabel("호스트명 (Zone 내 FQDN)").fill("new.example.invalid");
  await dialog.getByRole("textbox", { name: "값" }).fill("192.0.2.44");
  const execute = dialog.getByRole("button", { name: "모의 변경 실행" });
  await expect(execute).toBeDisabled();
  await dialog.getByRole("checkbox", { name: "변경 대상과 현재·변경 값을 확인했습니다." }).check();
  await execute.click();
  await expect(page.getByText("DEMO DNS 작업 완료")).toBeVisible();
  const history = page.getByRole("region", { name: "DNS 변경 기록" });
  await expect(history).toContainText("A new.example.invalid");
  await expect(history).toContainText("simulated");
});

test("unhealthy Docker containers are counted and filtered as problems", async ({ page }) => {
  await page.route("**/api/v1/resources/containers", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      key: "containers", mode: "live", status: "connected", message: "Portainer 상태 조회",
      updatedAt: "2026-11-09T00:00:00Z", metrics: [],
      columns: ["컨테이너", "상태", "이미지 · 포트", "갱신"],
      rows: [
        { id: "a".repeat(64), name: "unhealthy-web", status: "Up 3 days (unhealthy)", detail: "nginx:stable · 80/tcp", updatedAt: "2026-11-09T00:00:00Z" },
        { id: "b".repeat(64), name: "healthy-api", status: "Up 3 days", detail: "api:latest · 8080/tcp", updatedAt: "2026-11-09T00:00:00Z" },
        { id: "c".repeat(64), name: "paused-db", status: "Up 3 days (Paused)", detail: "postgres:16 · 5432/tcp", updatedAt: "2026-11-09T00:00:00Z" },
      ], actions: [],
    }),
  }));
  await page.goto("/containers");
  await page.getByRole("button", { name: "문제 1" }).click();
  await expect(page.getByRole("button", { name: "unhealthy-web" })).toBeVisible();
  await expect(page.getByRole("button", { name: "healthy-api" })).toHaveCount(0);
  await page.getByRole("button", { name: "실행 중 1" }).click();
  await expect(page.getByRole("button", { name: "healthy-api" })).toBeVisible();
  await expect(page.getByRole("button", { name: "unhealthy-web" })).toHaveCount(0);
  await page.getByRole("button", { name: "중지 1" }).click();
  await expect(page.getByRole("button", { name: "paused-db" })).toBeVisible();
});

test("overview SSE streams validated data through the same-origin proxy", async ({ page }) => {
  await page.goto("/");
  const payload = await page.evaluate(() => new Promise<{ mode: string; status: string }>((resolve, reject) => {
    const source = new EventSource("/api/v1/metrics/overview/stream");
    const timeout = window.setTimeout(() => {
      source.close();
      reject(new Error("SSE response timed out"));
    }, 5_000);
    source.onmessage = (event) => {
      window.clearTimeout(timeout);
      source.close();
      resolve(JSON.parse(event.data) as { mode: string; status: string });
    };
    source.onerror = () => {
      window.clearTimeout(timeout);
      source.close();
      reject(new Error("SSE connection failed"));
    };
  }));
  expect(payload.mode).toBe("mock");
  expect(payload.status).toBe("connected");
});

test("deployment page shows persisted job state", async ({ page }) => {
  await page.goto("/deployments");
  await page.getByRole("button", { name: "배포 시뮬레이션" }).click();
  await page.getByRole("button", { name: "모의 작업 실행" }).click();
  await page.getByRole("button", { name: /관리 작업 이력/ }).click();
  const history = page.getByRole("table", { name: "작업 이력" });
  const deploymentJob = history.getByRole("row").filter({ hasText: "deploy" }).first();
  await expect(deploymentJob.getByRole("cell").nth(1)).toHaveText("DEMO · succeeded");
});

test("live deployments are grouped by repository and remain read only", async ({ page }) => {
  await page.route("**/api/v1/resources/deployments", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      key: "deployments", mode: "live", status: "connected", message: "GitHub Actions read only",
      updatedAt: "2026-11-09T00:00:00Z",
      metrics: [{ label: "저장소", value: "2", detail: "허용 목록" }, { label: "최근 실행", value: "3", detail: "실행" }, { label: "권한", value: "읽기 전용", detail: "Actions: read" }, { label: "조회", value: "GitHub API", detail: "서버 요청" }],
      columns: ["저장소 · 워크플로", "상태", "실행 요약", "마지막 갱신"],
      rows: [
        { id: "owner/app-one#42", name: "owner/app-one · deploy", status: "success", detail: "Deploy · main · aaaaaaa · #42", updatedAt: "2026-11-09T00:00:00Z" },
        { id: "owner/app-one#41", name: "owner/app-one · tests", status: "failure", detail: "Tests · main · bbbbbbb · #41", updatedAt: "2026-11-08T00:00:00Z" },
        { id: "owner/app-two#7", name: "owner/app-two · build", status: "in_progress", detail: "Build · release · ccccccc · #7", updatedAt: "2026-11-09T00:00:00Z" },
      ], actions: [],
    }),
  }));
  await page.goto("/deployments");
  await expect(page.getByRole("button", { name: /owner\/app-one/ })).toBeVisible();
  await expect(page.getByText("GitHub Actions · 읽기 전용")).toBeVisible();
  await expect(page.getByRole("button", { name: /owner\/app-two/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /owner\/app-two/ })).toHaveCount(1);
  await expect(page.getByRole("link", { name: "GitHub에서 보기" })).toHaveAttribute("href", "https://github.com/owner/app-one/actions/runs/42");
  await expect(page.getByText("마지막 갱신")).toBeVisible();
  await expect(page.getByRole("button", { name: "배포 시작" })).toHaveCount(0);
  await page.getByRole("button", { name: /owner\/app-two/ }).click();
  await expect(page.getByRole("link", { name: "GitHub에서 보기" })).toHaveAttribute("href", "https://github.com/owner/app-two/actions/runs/7");
  await expect(page.getByText("마지막 갱신")).toBeVisible();
});

test("partial GitHub failures retain the live state and provider message", async ({ page }) => {
  await page.route("**/api/v1/resources/deployments", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      key: "deployments", mode: "live", status: "partial", message: "GitHub Actions 조회 실패: owner/app-two",
      updatedAt: "2026-11-09T00:00:00Z", metrics: [], columns: ["저장소", "상태", "실행", "갱신"],
      rows: [{ id: "owner/app-one#42", name: "owner/app-one · deploy", status: "success", detail: "Deploy · main · aaaaaaa · #42", updatedAt: "2026-11-09T00:00:00Z" }],
      actions: [],
    }),
  }));
  await page.goto("/deployments");
  await expect(page.getByText("부분 연결", { exact: true })).toBeVisible();
  await expect(page.getByText("GitHub Actions 조회 실패: owner/app-two")).toBeVisible();
  await expect(page.getByRole("button", { name: /owner\/app-one/ })).toBeVisible();
});

test("service page labels live Docker health conservatively", async ({ page }) => {
  await page.route("**/api/v1/resources/services", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      key: "services",
      mode: "live",
      status: "connected",
      message: "Portainer container status",
      updatedAt: "2026-11-09T00:00:00Z",
      metrics: [],
      columns: ["컨테이너", "상태", "이미지 · Docker 상태", "확인"],
      rows: [{
        id: "a".repeat(64),
        name: "Docker · web",
        status: "warning",
        detail: "nginx:stable · 실행 중 · Healthcheck 미보고",
        updatedAt: "2026-11-09T00:00:00Z",
      }],
      actions: [],
    }),
  }));
  await page.goto("/services");
  const row = page.getByRole("row", { name: /Docker · web/ });
  await expect(row).toContainText("주의");
  await expect(row).toContainText("Healthcheck 미보고");
});

test("passkey removal requires target confirmation and keeps Enter on cancel", async ({ page }) => {
  await page.route("**/api/v1/webauthn/status", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      bootstrapRequired: false,
      passkeys: [
        { id: "cGFzc2tleS0x", name: "MacBook", createdAt: "2026-11-09T00:00:00Z" },
        { id: "cGFzc2tleS0y", name: "Phone", createdAt: "2026-11-09T00:00:00Z" },
      ],
    }),
  }));
  await page.goto("/security");
  await page.getByRole("button", { name: "MacBook Passkey 삭제" }).click();
  const dialog = page.getByRole("dialog", { name: "Passkey 삭제" });
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("MacBook");
  await expect(dialog.getByRole("button", { name: "취소" })).toBeFocused();
  await expect(dialog).toHaveCSS("opacity", "1");
  const dialogA11y = await new AxeBuilder({ page }).include("dialog").analyze();
  expect(dialogA11y.violations.map(({ id, nodes }) => ({
    id,
    nodes: nodes.map(({ target, failureSummary }) => ({ target, failureSummary })),
  }))).toEqual([]);
  await page.keyboard.press("Enter");
  await expect(dialog).not.toBeVisible();
  await page.getByRole("button", { name: "MacBook Passkey 삭제" }).click();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
});

test("mobile quick navigation and empty search keep keyboard focus inside dialogs", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  const quickNav = page.getByRole("navigation", { name: "빠른 메뉴" });
  await expect(quickNav.getByRole("link", { name: "Docker" })).toHaveAttribute("href", "/containers");
  const moreButton = quickNav.getByRole("button", { name: "더보기" });
  await moreButton.click();
  const menu = page.getByRole("dialog", { name: "전체 메뉴" });
  const closeMenu = menu.getByRole("button", { name: "닫기" });
  await expect(closeMenu).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(menu.getByRole("link", { name: "배포" })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(closeMenu).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(menu).not.toBeVisible();
  await expect(moreButton).toBeFocused();

  const searchButton = page.getByRole("button", { name: "검색 ⌘ K" });
  await searchButton.click();
  const search = page.getByRole("dialog", { name: "페이지 검색" });
  const input = search.getByRole("textbox", { name: "페이지 이름으로 검색" });
  await input.fill("no-such-page");
  await expect(search.getByText("검색 결과가 없습니다.")).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(input).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(input).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(search).not.toBeVisible();
  await expect(searchButton).toBeFocused();
});

test("live connection labels agree across shell and overview", async ({ page }) => {
  await page.route("**/api/v1/metrics/overview", async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    await route.fulfill({ response, json: { ...body, mode: "live", status: "connected" } });
  });
  await page.goto("/");
  await expect(page.getByText("Live 연결", { exact: true })).toHaveCount(3);
});

test("layout has no document-level horizontal overflow at required widths", async ({ page }) => {
  for (const width of [320, 390, 430, 768, 1280, 1440, 1920]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "개요" })).toBeVisible();
    const sizes = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, page: document.documentElement.scrollWidth }));
    expect(sizes.page, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(sizes.viewport + 1);
    const scrollOwner = await page.evaluate(() => {
      const main = document.querySelector(".app-shell__main");
      const documentRoot = document.scrollingElement;
      return {
        mainScrolls: Boolean(main && main.scrollHeight > main.clientHeight + 1),
        documentScrolls: Boolean(documentRoot && documentRoot.scrollHeight > documentRoot.clientHeight + 1),
      };
    });
    expect(scrollOwner.documentScrolls, `document took scroll ownership at ${width}px`).toBe(false);
    if (width === 390 || width === 1440) expect(scrollOwner.mainScrolls, `main does not scroll at ${width}px`).toBe(true);
    if (width === 390 || width === 1440) {
      await expect(page.getByRole("heading", { name: "서비스 상태" })).toBeVisible();
      await page.screenshot({ path: `test-results/overview-${width}.png`, fullPage: true });
    }
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/containers");
  await expect(page.locator(".container-table-scroll tbody tr")).toBeVisible();
  expect(await page.locator(".container-table-scroll tbody tr").evaluate((row) => getComputedStyle(row).display)).toBe("block");
  const containerSizes = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, page: document.documentElement.scrollWidth }));
  expect(containerSizes.page).toBeLessThanOrEqual(containerSizes.viewport + 1);
});

test("all routes meet the selected WCAG 2.2 AA automated rules", async ({ page }) => {
  const routes = ["/", "/services", "/notifications", "/system", "/automation", "/domains", "/mail", "/database", "/storage", "/monitoring", "/security", "/settings", "/containers", "/images", "/stacks", "/deployments"];
  for (const route of routes) {
    const resourceResponse = route === "/" ? null : page.waitForResponse((response) => response.url().endsWith(`/api/v1/resources/${route.slice(1)}`));
    await page.goto(route);
    await expect(page.locator("h1")).toBeVisible();
    if (resourceResponse) expect((await resourceResponse).status()).toBe(200);
    await expect(page.locator('[aria-busy="true"]')).toHaveCount(0);
    await expect(page.locator(route === "/" ? ".panel--services" : ".resource-table-panel").first()).toBeVisible();
    if (route === "/images" || route === "/stacks") await expect(page.locator(".resource-table tbody tr")).toHaveCount(1);
    const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
    const failures = results.violations.map(({ id, help, nodes }) => ({ id, help, nodes: nodes.map(({ target, failureSummary }) => ({ target, failureSummary })) }));
    expect(failures, `accessibility violations at ${route}`).toEqual([]);
  }
});

test("PWA manifest icon is available", async ({ page, request }) => {
  await page.goto("/");
  await expect(page.locator('link[rel="manifest"]')).toHaveAttribute("href", "/manifest.webmanifest");
  const manifest = await request.get("/manifest.webmanifest");
  expect(manifest.ok()).toBeTruthy();
  const data = await manifest.json();
  expect(data.name).toBe("HomeServer Admin");
  const icon = await request.get(data.icons[0].src);
  expect(icon.ok()).toBeTruthy();
  expect(icon.headers()["content-type"]).toContain("image/svg+xml");
});
