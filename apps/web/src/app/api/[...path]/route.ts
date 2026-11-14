import type { NextRequest } from "next/server";

const resourceKeys = new Set([
  "services", "notifications", "system", "automation", "domains", "mail",
  "database", "storage", "monitoring", "security", "settings", "containers", "images", "stacks", "deployments",
]);
const streamPath = (path: string[]) => path.join("/") === "v1/metrics/overview/stream" ||
  (path.length === 5 && path[0] === "v1" && path[1] === "containers" &&
    (path[2] === "container" || /^[a-fA-F0-9]{12,64}$/.test(path[2])) &&
    path[3] === "logs" && path[4] === "stream");
const allowed = (method: string, path: string[]) =>
  (method === "GET" && (path.join("/") === "v1/metrics/overview" || path.join("/") === "v1/audit" || path.join("/") === "v1/jobs" || path.join("/") === "v1/webauthn/status" || streamPath(path) || (path.length === 3 && path[0] === "v1" && path[1] === "jobs" && /^[0-9a-f-]{36}$/.test(path[2])) || (path.length === 3 && path[0] === "v1" && path[1] === "resources" && resourceKeys.has(path[2])) || (path.length === 4 && path[0] === "v1" && path[1] === "containers" && (path[2] === "container" || /^[a-fA-F0-9]{12,64}$/.test(path[2])) && ["logs", "stats"].includes(path[3])))) ||
  (method === "POST" && (path.join("/") === "v1/jobs" || [
    "v1/webauthn/reauth/options",
    "v1/webauthn/reauth/verify",
    "v1/webauthn/register/options",
    "v1/webauthn/register/verify",
    "v1/webauthn/passkeys/delete",
  ].includes(path.join("/"))));

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  if (!path.length || path.some((segment) => !/^[a-zA-Z0-9_-]{1,64}$/.test(segment)) || !allowed(request.method, path)) {
    return Response.json({ detail: "Not found" }, { status: 404, headers: { "Cache-Control": "no-store" } });
  }

  let upstreamBase: URL;
  try {
    upstreamBase = new URL(process.env.API_INTERNAL_URL ?? "");
    if (
      upstreamBase.protocol !== "http:" ||
      !["api", "127.0.0.1", "localhost"].includes(upstreamBase.hostname) ||
      upstreamBase.port !== "8000"
    ) throw new Error();
    if (!(["http:", "https:"].includes(upstreamBase.protocol)) || upstreamBase.username || upstreamBase.password || upstreamBase.pathname !== "/" || upstreamBase.search || upstreamBase.hash) throw new Error();
  } catch {
    return Response.json({ detail: "API upstream is not configured" }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }

  const headers = new Headers({ Accept: streamPath(path) ? "text/event-stream" : "application/json" });
  const assertion = request.headers.get("cf-access-jwt-assertion");
  if (assertion) headers.set("Cf-Access-Jwt-Assertion", assertion);
  if (request.method === "POST") {
    const origin = request.headers.get("origin");
    let expectedOrigin = new URL(request.url).origin;
    try {
      if (process.env.WEB_ORIGIN) {
        const configured = new URL(process.env.WEB_ORIGIN);
        if (configured.origin !== process.env.WEB_ORIGIN || configured.username || configured.password) throw new Error();
        expectedOrigin = configured.origin;
      }
    } catch {
      return Response.json({ detail: "Web origin is not configured" }, { status: 503, headers: { "Cache-Control": "no-store" } });
    }
    if (origin !== expectedOrigin) {
      return Response.json({ detail: "Origin check failed" }, { status: 403, headers: { "Cache-Control": "no-store" } });
    }
    if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
      return Response.json({ detail: "JSON content type required" }, { status: 415, headers: { "Cache-Control": "no-store" } });
    }
    const declaredLength = Number(request.headers.get("content-length") ?? 0);
    if (declaredLength > 65_536) return Response.json({ detail: "Request too large" }, { status: 413 });
    const body = await readBody(request, 65_536);
    if (!body) return Response.json({ detail: "Request too large" }, { status: 413 });
    headers.set("Content-Type", "application/json");
    headers.set("X-HS-Origin-Verified", "1");
    return forward(request, upstreamBase, path, headers, body);
  }
  return forward(request, upstreamBase, path, headers);
}

async function forward(request: NextRequest, base: URL, path: string[], headers: Headers, body?: ArrayBuffer) {
  const target = new URL(`api/${path.map(encodeURIComponent).join("/")}`, base);
  target.search = request.nextUrl.search;
  const streaming = streamPath(path);
  try {
    const response = await fetch(target, {
      method: request.method,
      headers,
      body,
      cache: "no-store",
      signal: streaming ? request.signal : AbortSignal.any([request.signal, AbortSignal.timeout(12_000)]),
    });
    const outputHeaders = new Headers({ "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
    if (streaming) {
      outputHeaders.set("Cache-Control", "no-cache, no-transform");
      outputHeaders.set("X-Accel-Buffering", "no");
    }
    const type = response.headers.get("content-type");
    if (type) outputHeaders.set("Content-Type", type);
    const length = Number(response.headers.get("content-length") ?? 0);
    const responseLimit = path[1] === "containers" && path[3] === "logs" ? 7_000_000 : 1_048_576;
    if (length > responseLimit) return Response.json({ detail: "Upstream response too large" }, { status: 502, headers: outputHeaders });
    return new Response(response.body, { status: response.status, headers: outputHeaders });
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "TimeoutError";
    return Response.json({ detail: timedOut ? "API request timed out" : "API upstream unavailable" }, { status: timedOut ? 504 : 502, headers: { "Cache-Control": "no-store" } });
  }
}

async function readBody(request: Request, limit: number): Promise<ArrayBuffer | null> {
  const reader = request.body?.getReader();
  if (!reader) return new ArrayBuffer(0);
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  return new Blob(chunks.map((chunk) => new Uint8Array(chunk).buffer)).arrayBuffer();
}

export const GET = proxy;
export const POST = proxy;
