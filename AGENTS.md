# HomeServer Admin

## Structure

- `apps/web`: Next.js App Router, React, strict TypeScript, Tailwind CSS. Production hosting is Vercel. Local Compose still runs the web app for development.
- `apps/api`: FastAPI management API, Access verification, SQLite audit store, and provider adapters. Production keeps this API on the home server behind Cloudflare Access and Tunnel.
- `firmware/esp32-power`: reference ESP32 sketch that polls the Vercel app and pulses the PC power button.
- `apps/agent`: non-root read-only Linux metrics agent for selected `/proc` files, hwmon sensors, and explicitly approved storage probe files.
- `infra`: deployment and rollback helpers.
- Root `compose.*.yaml`: local and production services.
- Root docs: product, architecture, security, deployment, and design contracts.

Keep browser code limited to the HomeServer Admin API. Keep credentials and system access in server-side providers. Live features without a configured provider must report disconnected or unavailable.

## Commands

- Web development: `npm --prefix apps/web run dev`
- Web checks: `npm --prefix apps/web run lint`, `npm --prefix apps/web run typecheck`, `npm --prefix apps/web run build`
- API development: `cd apps/api && uv sync --locked --group dev && uv run uvicorn app.main:app --reload`
- API checks: `cd apps/api && uv run pytest && uv run ruff check app tests`
- Local stack: `docker compose -f compose.dev.yaml up --build`
- Agent checks: `python3 -m unittest discover -s apps/agent/tests -v`
- Deployment helper checks: `python3 -m unittest discover -s infra/tests -v`

Use Node.js 24 LTS and Python 3.14. Pin dependencies in their lockfiles. Keep TypeScript strict and validate API payloads at runtime with Zod/Pydantic.

## Development rules

- Read `DESIGN.md` before changing UI. Preserve the supplied dark palette, Pretendard, JetBrains Mono, navigation, responsive behavior, and interaction patterns.
- Mock mode is development-only. Never silently fall back to mock data when the API or a live integration is unavailable.
- Never expose API keys, Access assertions, or system credentials to browser code or logs.
- Never run web/API processes as root, mount the Docker socket into them, or execute arbitrary shell commands.
- Risky system actions require server-side authorization, reauthentication, explicit target confirmation, and an audit record. Keep web/API-triggered host commands, deployment, backup/restore, shutdown, and reboot disabled until their restricted providers are verified; fixed Compose and SQLite operator scripts may run only through SSH. Docker container start/stop/restart may use only the fixed Portainer adapter with a separate least-privilege key, Owner/Operator authorization, exact-container WebAuthn grants, and an audit record. Cloudflare DNS create/update/delete may use only a separate DNS Write token scoped to one configured zone, Owner authorization, a WebAuthn grant bound to the complete change, and before/after audit details. Remote power on/off may use only the Vercel power routes: an owner Access identity, a one-time WebAuthn grant stored with the power queue, a 30-second one-shot command, a per-device HMAC, and an audit record. The ESP32 may pulse the motherboard power-button header. It must not hold the button for a forced power-off.
- Do not alter the supplied design files or existing HDD data. Do not change production DNS, Cloudflare Access/Tunnel, or server configuration from this workspace.
- Add focused tests for non-trivial security, parsing, or state logic. Run the relevant check before reporting completion.

## Git

- Branches: `feat/<short-name>`, `fix/<short-name>`, or `docs/<short-name>`.
- Do not commit or push unless explicitly requested. Never rewrite shared history or force-push.
- Commit messages must be `prefix: description`, using one of `feat`, `fix`, `refactor`, `docs`, `style`, `test`, `chore`, `perf`, `ci`, or `build`. Keep them short and specific.

## Deployment

- Build production images for `linux/amd64`; also retain `linux/arm64` support for Mac development.
- Publish tagged releases to GHCR only after CI passes; deploy and roll back by recorded image digest, with release tag retained for readability.
- Keep the management API on an internal Docker network and attach only that API to the existing Cloudflare Tunnel. Host the Next.js app on Vercel so it stays reachable while the home PC is off. The Vercel server calls the API with a Cloudflare Access service token held in server environment variables. The browser never receives that token, the ESP32 device secret, or the power-store credential.
- Keep Tailscale SSH available as the recovery path. Do not deploy or modify external infrastructure without an explicit request.
