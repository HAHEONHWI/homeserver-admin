import { randomBytes, timingSafeEqual } from "node:crypto";
import { PowerHttpError } from "./errors.ts";
import {
  ACK_TTL_SECONDS,
  AUDIT_LIMIT,
  COMMAND_TTL_SECONDS,
  GRANT_TTL_SECONDS,
  HEARTBEAT_TTL_SECONDS,
  INFLIGHT_TTL_SECONDS,
  OWNER_RATE_LIMIT,
  powerKeys,
  subjectHash,
} from "./keys.ts";
import type { PowerStore } from "./store.ts";

export type PowerAction = "power_on" | "power_off";
export type PowerState = "on" | "off" | "unknown";
export type AckResult = "done" | "rejected" | "failed";
export type AckDisposition = "recorded" | "duplicate" | "rejected" | "ignored";

const COMMAND_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const GRANT_TOKEN = /^[A-Za-z0-9_-]{43}$/;

export type PublicCommand = { id: string; action: PowerAction; expiresAt: string };
export type AuditEvent = {
  id: string;
  at: string;
  actor: string;
  kind: "queue" | "replace" | "deliver" | "expire" | "ack" | "reject" | "enroll" | "remove";
  action?: PowerAction;
  commandId?: string;
  result?: AckResult;
  detail?: string;
};
type StoredCommand = PublicCommand & { actor: string };
export type Heartbeat = { state: PowerState; firmware: string; seenAt: string };

export async function issueGrant(store: PowerStore, subject: string, operation: string, target: string): Promise<string> {
  const token = randomBytes(32).toString("base64url");
  await store.set(powerKeys.grant(token), JSON.stringify({ subject, operation, target }), { ttlSeconds: GRANT_TTL_SECONDS });
  return token;
}

export async function consumeGrant(store: PowerStore, token: string, subject: string, operation: string, target: string): Promise<boolean> {
  if (!GRANT_TOKEN.test(token)) return false;
  const raw = await store.getDel(powerKeys.grant(token));
  if (!raw) return false;
  const parsed = parseObject(raw);
  return parsed?.subject === subject && parsed.operation === operation && parsed.target === target;
}

export function bootstrapMatches(provided: string, expected: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(expected) || !/^[0-9a-f]{64}$/.test(provided)) return false;
  return timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
}

export async function assertOwnerRate(store: PowerStore, subject: string, bucket: "write" | "read" = "write"): Promise<void> {
  const limit = bucket === "write" ? OWNER_RATE_LIMIT : 120;
  const hits = await store.increment(powerKeys.rate(`owner:${bucket}:${subjectHash(subject)}`), 60);
  if (hits > limit) throw new PowerHttpError(429, "Too many power requests");
}

export async function enqueueCommand(input: {
  store: PowerStore;
  deviceId: string;
  action: PowerAction;
  actor: string;
  nowMs?: number;
}): Promise<PublicCommand> {
  const nowMs = input.nowMs ?? Date.now();
  const command: StoredCommand = {
    id: crypto.randomUUID(),
    action: input.action,
    expiresAt: new Date(nowMs + COMMAND_TTL_SECONDS * 1000).toISOString(),
    actor: input.actor,
  };
  const key = powerKeys.pending(input.deviceId);
  const previous = parseCommand(await input.store.get(key));
  await input.store.set(key, JSON.stringify(command), { ttlSeconds: COMMAND_TTL_SECONDS });
  await recordAudit(input.store, input.deviceId, {
    actor: input.actor,
    kind: previous ? "replace" : "queue",
    action: input.action,
    commandId: command.id,
    detail: previous ? previous.id : undefined,
  }, nowMs);
  return publicCommand(command);
}

export async function handleDevicePoll(input: {
  store: PowerStore;
  deviceId: string;
  body: unknown;
  nowMs?: number;
}): Promise<{ command: PublicCommand | null; ack: AckDisposition }> {
  const nowMs = input.nowMs ?? Date.now();
  const report = parsePoll(input.body);
  await input.store.set(powerKeys.state(input.deviceId), JSON.stringify({
    state: report.state,
    firmware: report.firmware,
    seenAt: new Date(nowMs).toISOString(),
  }), { ttlSeconds: HEARTBEAT_TTL_SECONDS });
  const ack = report.ack
    ? await recordAck(input.store, input.deviceId, report.ack, nowMs)
    : "ignored";
  const command = await takePending(input.store, input.deviceId, nowMs);
  return { command, ack };
}

export async function readPowerView(store: PowerStore, deviceId: string, nowMs = Date.now()): Promise<{
  heartbeat: Heartbeat | null;
  online: boolean;
  pending: PublicCommand | null;
  inflight: PublicCommand | null;
  audit: AuditEvent[];
}> {
  const heartbeat = parseHeartbeat(await store.get(powerKeys.state(deviceId)));
  const pending = publicOrNull(parseCommand(await store.get(powerKeys.pending(deviceId))), nowMs);
  const inflight = publicOrNull(parseCommand(await store.get(powerKeys.inflight(deviceId))), nowMs);
  const audit = (await store.range(powerKeys.audit(deviceId), 0, AUDIT_LIMIT - 1))
    .map(parseAudit)
    .filter((event): event is AuditEvent => event !== null);
  const online = Boolean(heartbeat && nowMs - Date.parse(heartbeat.seenAt) <= HEARTBEAT_TTL_SECONDS * 1000);
  return { heartbeat, online, pending, inflight, audit };
}

export async function recordAudit(store: PowerStore, deviceId: string, event: Omit<AuditEvent, "id" | "at">, nowMs = Date.now()): Promise<void> {
  const record: AuditEvent = {
    id: crypto.randomUUID(),
    at: new Date(nowMs).toISOString(),
    actor: event.actor,
    kind: event.kind,
    action: event.action,
    commandId: event.commandId,
    result: event.result,
    detail: cleanDetail(event.detail),
  };
  await store.pushTrim(powerKeys.audit(deviceId), JSON.stringify(record), AUDIT_LIMIT);
}

async function takePending(store: PowerStore, deviceId: string, nowMs: number): Promise<PublicCommand | null> {
  const stored = parseCommand(await store.getDel(powerKeys.pending(deviceId)));
  if (!stored) return null;
  if (Date.parse(stored.expiresAt) <= nowMs) {
    await recordAudit(store, deviceId, {
      actor: "device",
      kind: "expire",
      action: stored.action,
      commandId: stored.id,
    }, nowMs);
    return null;
  }
  await store.set(powerKeys.inflight(deviceId), JSON.stringify(stored), { ttlSeconds: INFLIGHT_TTL_SECONDS });
  await recordAudit(store, deviceId, {
    actor: "device",
    kind: "deliver",
    action: stored.action,
    commandId: stored.id,
  }, nowMs);
  return publicCommand(stored);
}

async function recordAck(store: PowerStore, deviceId: string, ack: { id: string; result: AckResult; detail?: string }, nowMs: number): Promise<AckDisposition> {
  const ackKey = powerKeys.ack(deviceId, ack.id);
  if (await store.get(ackKey)) return "duplicate";
  const inflight = parseCommand(await store.get(powerKeys.inflight(deviceId)));
  if (!inflight || inflight.id !== ack.id) {
    await recordAudit(store, deviceId, {
      actor: "device",
      kind: "reject",
      commandId: ack.id,
      result: ack.result,
      detail: "ack did not match the delivered command",
    }, nowMs);
    return "rejected";
  }
  const saved = await store.set(ackKey, ack.result, { ttlSeconds: ACK_TTL_SECONDS, nx: true });
  if (saved !== "OK") return "duplicate";
  await store.getDel(powerKeys.inflight(deviceId));
  await recordAudit(store, deviceId, {
    actor: "device",
    kind: "ack",
    action: inflight.action,
    commandId: ack.id,
    result: ack.result,
    detail: ack.detail,
  }, nowMs);
  return "recorded";
}

function parsePoll(body: unknown): { state: PowerState; firmware: string; ack: { id: string; result: AckResult; detail?: string } | null } {
  const value = asObject(body);
  if (!value) throw new PowerHttpError(400, "Invalid device report");
  const allowed = new Set(["state", "firmware", "ack"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) throw new PowerHttpError(400, "Invalid device report");
  if (value.state !== "on" && value.state !== "off" && value.state !== "unknown") {
    throw new PowerHttpError(400, "Invalid device report");
  }
  const firmware = typeof value.firmware === "string" && /^[A-Za-z0-9._-]{1,40}$/.test(value.firmware) ? value.firmware : "";
  if (value.ack === undefined || value.ack === null) return { state: value.state, firmware, ack: null };
  const ack = asObject(value.ack);
  const result = ack?.result;
  if (!ack || typeof ack.id !== "string" || !COMMAND_ID.test(ack.id) || (result !== "done" && result !== "rejected" && result !== "failed")) {
    throw new PowerHttpError(400, "Invalid device report");
  }
  return { state: value.state, firmware, ack: { id: ack.id, result, detail: cleanDetail(ack.detail) } };
}

function parseCommand(raw: string | null): StoredCommand | null {
  if (!raw) return null;
  const value = parseObject(raw);
  if (!value || typeof value.id !== "string" || !COMMAND_ID.test(value.id)) return null;
  if (value.action !== "power_on" && value.action !== "power_off") return null;
  if (typeof value.expiresAt !== "string" || Number.isNaN(Date.parse(value.expiresAt))) return null;
  if (typeof value.actor !== "string" || value.actor.length > 254) return null;
  return { id: value.id, action: value.action, expiresAt: value.expiresAt, actor: value.actor };
}

function parseHeartbeat(raw: string | null): Heartbeat | null {
  if (!raw) return null;
  const value = parseObject(raw);
  if (!value || (value.state !== "on" && value.state !== "off" && value.state !== "unknown")) return null;
  if (typeof value.seenAt !== "string" || Number.isNaN(Date.parse(value.seenAt))) return null;
  const firmware = typeof value.firmware === "string" ? value.firmware : "";
  return { state: value.state, firmware, seenAt: value.seenAt };
}

function parseAudit(raw: string): AuditEvent | null {
  const value = parseObject(raw);
  if (!value || typeof value.id !== "string" || typeof value.at !== "string" || typeof value.actor !== "string" || typeof value.kind !== "string") {
    return null;
  }
  return value as AuditEvent;
}

function publicOrNull(command: StoredCommand | null, nowMs: number): PublicCommand | null {
  if (!command || Date.parse(command.expiresAt) <= nowMs) return null;
  return publicCommand(command);
}

function publicCommand(command: StoredCommand): PublicCommand {
  return { id: command.id, action: command.action, expiresAt: command.expiresAt };
}

function cleanDetail(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const detail = value.replace(/[\u0000-\u001f\u007f]/g, "").trim();
  return detail ? detail.slice(0, 120) : undefined;
}

function parseObject(raw: string): Record<string, unknown> | null {
  try {
    return asObject(JSON.parse(raw));
  } catch {
    return null;
  }
}

function asObject(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}
