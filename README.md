# HomeServer Admin

Next.js and FastAPI administration dashboard for `heonhwi-homeserver`. UI follows the supplied Claude design. Development defaults to clearly labeled Mock data; Live mode requires server-side Access validation and can use read-only Linux metrics, Portainer, PostgreSQL, Redis, mailcow, n8n/OpenClaw health checks, GitHub Actions, Cloudflare DNS, and ntfy providers. The web app does not expose host control, project deployment, backup, or restore actions. Operator-invoked Compose deploy/rollback and SQLite backup/restore scripts are provided for SSH use. Fixed Docker container controls and one-zone Cloudflare DNS writes are optional and require separate credentials, role checks, and Passkey reauthentication.

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
npm --prefix apps/web run build
npm --prefix apps/web run test:e2e
cd apps/api && uv sync --locked --group dev && uv run pytest && uv run ruff check app tests
python3 -m unittest discover -s apps/agent/tests -v
python3 -m unittest discover -s infra/tests -v
```

The Playwright checks start a local development API and web server. They cover Mock actions and persisted job history, audit display, the required viewport widths, and automated accessibility rules.

CI runs linux/amd64 API and web image smoke checks under a Sandy Bridge CPU model with AVX2 unavailable before publishing GHCR images.

## Docs

- [Architecture](ARCHITECTURE.md)
- [Security](SECURITY.md)
- [Deployment](DEPLOYMENT.md)
- [Design system](DESIGN.md)
- [Project instructions](AGENTS.md)
