import { PowerHttpError } from "./errors.ts";

export interface PowerStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options?: { ttlSeconds?: number; nx?: boolean }): Promise<"OK" | null>;
  getDel(key: string): Promise<string | null>;
  increment(key: string, ttlSeconds: number): Promise<number>;
  pushTrim(key: string, value: string, max: number): Promise<void>;
  range(key: string, start: number, stop: number): Promise<string[]>;
}

type MemoryEntry = { value: string; expiresAt: number | null };

export class MemoryPowerStore implements PowerStore {
  now: () => number = () => Date.now();
  private readonly values = new Map<string, MemoryEntry>();
  private readonly lists = new Map<string, string[]>();

  private live(key: string): MemoryEntry | null {
    const entry = this.values.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && entry.expiresAt <= this.now()) {
      this.values.delete(key);
      return null;
    }
    return entry;
  }

  async get(key: string): Promise<string | null> {
    return this.live(key)?.value ?? null;
  }

  async set(key: string, value: string, options?: { ttlSeconds?: number; nx?: boolean }): Promise<"OK" | null> {
    guardRecord(key, value);
    if (options?.nx && this.live(key)) return null;
    const ttl = options?.ttlSeconds;
    this.values.set(key, {
      value,
      expiresAt: ttl ? this.now() + ttl * 1000 : null,
    });
    return "OK";
  }

  async getDel(key: string): Promise<string | null> {
    const entry = this.live(key);
    this.values.delete(key);
    return entry?.value ?? null;
  }

  async increment(key: string, ttlSeconds: number): Promise<number> {
    const current = this.live(key);
    if (!current) {
      this.values.set(key, { value: "1", expiresAt: this.now() + ttlSeconds * 1000 });
      return 1;
    }
    const next = Number(current.value) + 1;
    current.value = String(next);
    return next;
  }

  async pushTrim(key: string, value: string, max: number): Promise<void> {
    guardRecord(key, value);
    const list = this.lists.get(key) ?? [];
    list.unshift(value);
    this.lists.set(key, list.slice(0, max));
  }

  async range(key: string, start: number, stop: number): Promise<string[]> {
    const list = this.lists.get(key) ?? [];
    return list.slice(start, stop + 1);
  }
}

export function assertUpstashUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new PowerHttpError(503, "Power store is not configured");
  }
  const hostname = url.hostname.toLowerCase();
  if (
    url.protocol !== "https:"
    || url.username
    || url.password
    || url.port
    || url.search
    || url.hash
    || (url.pathname !== "/" && url.pathname !== "")
    || !hostname.endsWith(".upstash.io")
    || hostname === "upstash.io"
    || hostname.includes("..")
  ) {
    throw new PowerHttpError(503, "Power store is not configured");
  }
  return url;
}

export class UpstashPowerStore implements PowerStore {
  private readonly endpoint: string;
  private readonly token: string;

  constructor(url: string, token: string) {
    this.token = token;
    this.endpoint = assertUpstashUrl(url).toString();
    if (token.length < 16 || token.length > 512 || !/^[\x21-\x7e]+$/.test(token)) {
      throw new PowerHttpError(503, "Power store is not configured");
    }
  }

  async get(key: string): Promise<string | null> {
    const result = await this.call(["GET", key]);
    return typeof result === "string" ? result : null;
  }

  async set(key: string, value: string, options?: { ttlSeconds?: number; nx?: boolean }): Promise<"OK" | null> {
    guardRecord(key, value);
    const args = ["SET", key, value];
    if (options?.ttlSeconds) args.push("EX", String(options.ttlSeconds));
    if (options?.nx) args.push("NX");
    const result = await this.call(args);
    return result === "OK" ? "OK" : null;
  }

  async getDel(key: string): Promise<string | null> {
    const result = await this.call(["GETDEL", key]);
    return typeof result === "string" ? result : null;
  }

  async increment(key: string, ttlSeconds: number): Promise<number> {
    await this.call(["SET", key, "0", "EX", String(ttlSeconds), "NX"]);
    const value = await this.call(["INCR", key]);
    await this.call(["EXPIRE", key, String(ttlSeconds), "NX"]);
    if (typeof value !== "number" || !Number.isFinite(value)) {
      throw new PowerHttpError(503, "Power store is unavailable");
    }
    return value;
  }

  async pushTrim(key: string, value: string, max: number): Promise<void> {
    guardRecord(key, value);
    await this.call(["LPUSH", key, value]);
    await this.call(["LTRIM", key, "0", String(max - 1)]);
  }

  async range(key: string, start: number, stop: number): Promise<string[]> {
    const result = await this.call(["LRANGE", key, String(start), String(stop)]);
    if (!Array.isArray(result) || result.some((item) => typeof item !== "string")) return [];
    return result;
  }

  private async call(command: string[]): Promise<unknown> {
    let response: Response;
    try {
      response = await fetch(this.endpoint, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(command),
        cache: "no-store",
        signal: AbortSignal.timeout(4_000),
      });
    } catch {
      throw new PowerHttpError(503, "Power store is unavailable");
    }
    if (!response.ok) throw new PowerHttpError(503, "Power store is unavailable");
    let payload: { result?: unknown; error?: string };
    try {
      payload = await response.json() as { result?: unknown; error?: string };
    } catch {
      throw new PowerHttpError(503, "Power store is unavailable");
    }
    if (payload.error) throw new PowerHttpError(503, "Power store is unavailable");
    return payload.result ?? null;
  }
}

function guardRecord(key: string, value: string): void {
  if (key.length < 1 || key.length > 200 || value.length > 8_192) {
    throw new PowerHttpError(400, "Power record is too large");
  }
}

let memoryStore: MemoryPowerStore | null = null;

export function storeCredentials(env: Record<string, string | undefined> = process.env): { url: string; token: string } | null {
  const pairs: Array<[string | undefined, string | undefined]> = [
    [env.POWER_STORE_REST_URL, env.POWER_STORE_REST_TOKEN],
    [env.UPSTASH_REDIS_REST_URL, env.UPSTASH_REDIS_REST_TOKEN],
    [env.KV_REST_API_URL, env.KV_REST_API_TOKEN],
  ];
  for (const [url, token] of pairs) {
    const trimmedUrl = url?.trim() ?? "";
    const trimmedToken = token?.trim() ?? "";
    if (trimmedUrl && trimmedToken) return { url: trimmedUrl, token: trimmedToken };
    if (trimmedUrl || trimmedToken) throw new PowerHttpError(503, "Power store is not configured");
  }
  return null;
}

export function powerStore(env: NodeJS.ProcessEnv = process.env): PowerStore {
  const credentials = storeCredentials(env);
  if (credentials) return new UpstashPowerStore(credentials.url, credentials.token);
  if (env.VERCEL || env.VERCEL_ENV) throw new PowerHttpError(503, "Power store is not configured");
  if (env.NODE_ENV === "production" && env.POWER_DEV_AUTH !== "1") {
    throw new PowerHttpError(503, "Power store is not configured");
  }
  memoryStore ??= new MemoryPowerStore();
  return memoryStore;
}
