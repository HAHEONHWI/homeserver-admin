# Architecture

## Request path

```text
Browser -> Cloudflare Access -> Vercel Next.js
  |-> /api/power/*  owner Access JWT, WebAuthn reauth, Upstash command queue -> ESP32 on home Wi-Fi
  \-> /api/v1/*     server-side Access service token -> Cloudflare Access -> Tunnel -> FastAPI -> provider adapters
```

The browser calls same-origin `/api` paths on the Vercel app. Management paths are proxied to the public FastAPI origin. The proxy adds the Cloudflare Access service-token headers and forwards the user Access JWT in `X-HS-User-Access-Jwt`, because presenting the service token can replace `Cf-Access-Jwt-Assertion`. FastAPI verifies that signed user JWT, issuer, audience, and expiry, then applies Owner/Operator/Viewer authorization. Local development still proxies to `http://api:8000` or loopback without a service token. Overview and container-log Server-Sent Event streams stay limited to 60 seconds, 32 concurrent connections per API process, and 4 per Access subject. A separate read-only Linux Agent exposes selected `/proc` metrics and supported hwmon temperatures over an internal, token-protected network. Host-level mutations remain disabled except the guarded power pulse, fixed Portainer container actions, and scoped Cloudflare DNS writes. No app container receives the Docker socket or arbitrary shell access.

When the home PC is off, the management proxy returns 502/504 and the UI shows the PC as offline. The power page does not depend on FastAPI. It reads the Vercel power store, so the owner can still enqueue a power-on command.

## Modules

- `apps/web`: App Router shell and routes, design tokens, typed API client, Zod response schemas, TanStack Query, and the Vercel power command routes. Production web hosting is Vercel. `compose.dev.yaml` still builds the web image for local Mock mode.
- `firmware/esp32-power`: Arduino reference sketch. Wi-Fi, the device id, the device secret, and the TLS CA come from gitignored `config.h`.
- `apps/api`: versioned FastAPI routes, Access authentication, role checks, SQLite audit/settings/passkeys, server-side WebAuthn challenge verification and scoped reauthentication grants, and Linux, Portainer, PostgreSQL, Redis, mailcow, n8n/OpenClaw health, n8n execution metadata, Netdata Agent alerts, Scrutiny device summaries, GitHub Actions, and Cloudflare DNS providers; optional ntfy delivery reports alert transitions. Scrutiny reads `GET /api/summary` and returns bounded device health, temperature, and power-on-hour fields without serials, WWN, or raw history. Portainer container start/stop/restart uses a separate fixed-path adapter with one-time target-bound grants. Cloudflare DNS writes use a separate one-zone token, Owner-only grants bound to the full change, current-record checks, and before/after audit history.
- Docker container health appears in Overview and the services page. A container is healthy only when Portainer reports an explicit healthy Healthcheck; running containers without one show a warning. Container and image inventory plus selected-container stats use bounded read-only Portainer requests. The Docker detail view keeps at most 24 Live samples in the browser for its CPU/memory trend; Mock data is not extended into fabricated history. Fixed start/stop/restart actions require the separate Portainer control key, Owner/Operator access, a one-time WebAuthn grant scoped to the exact container and operation, and a recorded result; all other Docker mutations remain unavailable.
- `apps/agent`: authenticated read-only OS identity, kernel version, CPU model/topology and temperatures, supported GPU temperatures, memory, swap, network, load, and uptime sampling; optional storage capacity from explicitly bind-mounted probe files.
- `infra`: Compose, image build, backups, deployment, and rollback scripts.

## Modes

- Development/Mock: explicit API mode and demo labeling; destructive/system operations return simulated outcomes only.
- Production/Live: startup fails closed without Access issuer/audience configuration. The overview uses real host metrics when the read-only agent responds and storage capacity only for explicitly mounted SSD/HDD paths; container, selected-container stats, image, Compose stack, and log reads use Portainer when configured; PostgreSQL and Redis report bounded read-only metrics; n8n readiness and OpenClaw gateway liveness use fixed HTTP GET probes; n8n execution metadata is fetched only with an API key and excludes execution data; Netdata reports a bounded set of current WARNING/CRITICAL alerts for one configured Agent; optional Scrutiny reads a bounded `/api/summary` for device health, temperature, and power-on hours; deployment history and mailcow domains/mailboxes/aliases use allowlisted read-only providers; Cloudflare DNS reads are zone-scoped and optional A/AAAA/CNAME/TXT/MX writes are Owner-only and Passkey-confirmed; ntfy can deliver host, Docker, and configured automation health transitions. Mail directory access is limited to Owner and Operator. Uptime Kuma remains unconfigured. Unsupported integrations report `not_configured`. No UI fallback supplies mock values.

## Async work

The API persists Mock job results and exposes authenticated job-list and job-status reads. Live mode can read recent GitHub Actions runs from an explicit repository allowlist with an Actions-read token. The web app has no Live job runner for deploy, rollback, backup, restore, or systemd operations; fixed Compose and SQLite scripts are operator-invoked over SSH. Portainer container actions and Cloudflare DNS writes have separate guarded providers. Remote power is a separate Vercel queue, not a FastAPI job: the owner reauthenticates with a power Passkey, the server stores one command for 30 seconds, and the ESP32 consumes it once. Other Live mutations fail closed until a restricted provider, reauthentication, and audit-backed completion checks exist.

## Power path

The persistent store is Upstash Redis over its HTTPS REST API. Vercel KV and the Upstash marketplace integration expose the same REST URL and token. `POWER_STORE_REST_URL` and `POWER_STORE_REST_TOKEN` are preferred. `UPSTASH_REDIS_REST_URL`/`UPSTASH_REDIS_REST_TOKEN` and `KV_REST_API_URL`/`KV_REST_API_TOKEN` are accepted only when the preferred pair is unset. A partial pair fails closed. Vercel refuses the in-process memory store. Local development may use memory when `POWER_DEV_AUTH=1` and the process is not running on Vercel.

Device requests sign `timestamp`, `nonce`, `POST`, `/api/power/device/poll`, and the SHA-256 of the raw body with HMAC-SHA256. The key is 32 bytes decoded from `POWER_DEVICE_SECRET`. Nonces last 120 seconds. Clock skew is 60 seconds. The queue holds one command per device. A newer owner command replaces an unclaimed one. Delivery uses a single get-and-delete. The device reports `done`, `rejected`, or `failed` on a later poll, and a repeated ack does not create a second audit row. Power Passkeys, challenges, grants, heartbeats, and the audit list live in the same store. Grants last 60 seconds, bind the owner, action, and device id, and are consumed once. The first Passkey for an owner requires `POWER_BOOTSTRAP_TOKEN`.
