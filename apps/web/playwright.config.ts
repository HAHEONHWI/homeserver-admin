import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  reporter: "list",
  use: { baseURL: "http://127.0.0.1:3000", trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: "uv run --directory ../api uvicorn app.main:app --host 127.0.0.1 --port 8000",
      url: "http://127.0.0.1:8000/health",
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      env: { APP_ENV: "development", APP_MODE: "mock", APP_DATA_DIR: `/tmp/homeserver-admin-playwright-${process.pid}` },
    },
    {
      command: "npm run build && mkdir -p .next/standalone/.next && cp -R .next/static .next/standalone/.next/static && cp -R public .next/standalone/public && node .next/standalone/server.js",
      url: "http://127.0.0.1:3000",
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      env: { API_INTERNAL_URL: "http://127.0.0.1:8000", WEB_ORIGIN: "http://127.0.0.1:3000", HOSTNAME: "127.0.0.1", PORT: "3000" },
    },
  ],
});
