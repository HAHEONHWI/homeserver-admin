import { PowerHttpError } from "./errors.ts";

export function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
  });
}

export function powerError(error: unknown): Response {
  if (error instanceof PowerHttpError) return json({ detail: error.message }, error.status);
  if (error instanceof SyntaxError) return json({ detail: "Invalid request" }, 400);
  console.error("power request failed");
  return json({ detail: "Power request failed" }, 500);
}

export function assertJson(request: Request): void {
  const type = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (type !== "application/json") throw new PowerHttpError(415, "JSON content type required");
}

export async function readBytes(request: Request, limit: number): Promise<Uint8Array> {
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (Number.isFinite(declared) && declared > limit) throw new PowerHttpError(413, "Request too large");
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new PowerHttpError(413, "Request too large");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

export async function readJson(request: Request, limit: number): Promise<Record<string, unknown>> {
  assertJson(request);
  const bytes = await readBytes(request, limit);
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new PowerHttpError(400, "Invalid request");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new PowerHttpError(400, "Invalid request");
  return parsed as Record<string, unknown>;
}
