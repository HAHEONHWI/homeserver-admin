# HomeServer Admin

Next.js and FastAPI administration dashboard for `heonhwi-homeserver`. UI follows the supplied Claude design. The production Next.js app is hosted on Vercel so it stays online when the home PC is off. Metrics, Docker, DNS, mail, and the other PC management APIs stay on the FastAPI service behind Cloudflare Access and Tunnel. A power page can queue a short power-button pulse for an ESP32 on the home Wi-Fi. Development defaults to clearly labeled Mock data; Live mode requires server-side Access validation and can use read-only Linux metrics, Portainer, PostgreSQL, Redis, mailcow, n8n/OpenClaw health checks, GitHub Actions, Cloudflare DNS, and ntfy providers. The web app does not expose host shell control, project deployment, backup, or restore actions. Operator-invoked Compose deploy/rollback and SQLite backup/restore scripts are provided for SSH use. Fixed Docker container controls, one-zone Cloudflare DNS writes, and the ESP32 power pulse are optional and require separate credentials, role checks, and Passkey reauthentication.

## Requirements

- Node.js 24 LTS (`.nvmrc`)
- Python 3.14 (`.python-version`)
- Docker Engine and Compose for the local stack

## Start

```sh
if [ ! -e .env ]; then (umask 077 && cp .env.example .env); fi
chmod 600 .env
docker compose -f compose.dev.yaml up --build
```

Open `http://localhost:3000`. To run only the web app, start the API separately and use `npm --prefix apps/web run dev`.

## Checks

```sh
npm --prefix apps/web run lint
npm --prefix apps/web run typecheck
npm --prefix apps/web run test
npm --prefix apps/web run build
npm --prefix apps/web run test:e2e
cd apps/api && uv sync --locked --group dev && uv run pytest && uv run ruff check app tests
python3 -m unittest discover -s apps/agent/tests -v
python3 -m unittest discover -s infra/tests -v
```

The Playwright checks start a local development API and web server. They cover Mock actions and persisted job history, audit display, the required viewport widths, and automated accessibility rules.

CI runs linux/amd64 API and local web image smoke checks under a Sandy Bridge CPU model with AVX2 unavailable. Tagged releases publish the API and read-only Agent images to GHCR. The production web app is deployed from the Vercel project, not from a GHCR web image.

## Docs

- [Architecture](ARCHITECTURE.md)
- [Security](SECURITY.md)
- [Deployment](DEPLOYMENT.md)
- [Design system](DESIGN.md)
- [Project instructions](AGENTS.md)
