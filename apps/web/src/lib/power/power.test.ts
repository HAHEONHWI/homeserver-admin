import assert from "node:assert/strict";
import { test } from "node:test";
import { PowerHttpError } from "./errors.ts";
import { MemoryPowerStore, assertUpstashUrl, storeCredentials } from "./store.ts";
import { authenticateDevice, signDeviceRequest } from "./protocol.ts";
import {
  consumeGrant,
  enqueueCommand,
  handleDevicePoll,
  issueGrant,
  readPowerView,
} from "./commands.ts";
import { COMMAND_TTL_SECONDS, DEVICE_RATE_LIMIT } from "./keys.ts";
import { isOwnerEmail, parseOwnerEmails } from "./access.ts";

const deviceId = "home-pc";
const secret = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const nowSeconds = 1_700_000_000;

function signed(body: Buffer, nonce = "nonce-value-0001", timestamp = String(nowSeconds)) {
  return {
    body,
    nonce,
    timestamp,
    signature: signDeviceRequest(secret, timestamp, nonce, body),
  };
}

async function authed(store: MemoryPowerStore, request: ReturnType<typeof signed>, expected = deviceId) {
  await authenticateDevice({
    store,
    secret,
    deviceId: expected,
    expectedDeviceId: deviceId,
    timestamp: request.timestamp,
    nonce: request.nonce,
    signature: request.signature,
    body: request.body,
    nowSeconds,
  });
}

test("device HMAC accepts one request and rejects tampering, skew, and replay", async () => {
  const store = new MemoryPowerStore();
  const body = Buffer.from(JSON.stringify({ state: "off", firmware: "0.1.0", ack: null }));
  await authed(store, signed(body));

  const tampered = Buffer.from(JSON.stringify({ state: "on", firmware: "0.1.0", ack: null }));
  await assert.rejects(
    () => authed(store, { ...signed(body, "nonce-value-0002"), body: tampered }),
    (error: unknown) => error instanceof PowerHttpError && error.status === 401,
  );

  await assert.rejects(
    () => authed(store, signed(body, "nonce-value-0003", String(nowSeconds - 120))),
    (error: unknown) => error instanceof PowerHttpError && error.message === "Stale device request",
  );

  await assert.rejects(
    () => authed(store, signed(body)),
    (error: unknown) => error instanceof PowerHttpError && error.message === "Replay rejected",
  );

  await assert.rejects(
    () => authed(store, signed(body, "nonce-value-0004"), "other-device"),
    (error: unknown) => error instanceof PowerHttpError && error.status === 401,
  );
  assert.equal(await store.get("power:v1:nonce:home-pc:nonce-value-0004"), null);
});

test("pending power commands expire, are delivered once, and record a single ack", async () => {
  const store = new MemoryPowerStore();
  const nowMs = nowSeconds * 1000;
  const first = await enqueueCommand({ store, deviceId, action: "power_on", actor: "owner@example.com", nowMs });
  const replacement = await enqueueCommand({ store, deviceId, action: "power_off", actor: "owner@example.com", nowMs });
  const pollBody = { state: "off", firmware: "0.1.0", ack: null };
  const delivered = await handleDevicePoll({ store, deviceId, body: pollBody, nowMs });

  assert.equal(delivered.command?.id, replacement.id);
  assert.notEqual(delivered.command?.id, first.id);
  assert.equal(delivered.command?.action, "power_off");
  assert.equal(delivered.ack, "ignored");
  assert.deepEqual(Object.keys(delivered.command ?? {}), ["id", "action", "expiresAt"]);

  const empty = await handleDevicePoll({ store, deviceId, body: pollBody, nowMs: nowMs + 1_000 });
  assert.equal(empty.command, null);

  const acked = await handleDevicePoll({
    store,
    deviceId,
    body: { state: "off", ack: { id: replacement.id, result: "done", detail: "pulsed" } },
    nowMs: nowMs + 2_000,
  });
  assert.equal(acked.ack, "recorded");
  const duplicate = await handleDevicePoll({
    store,
    deviceId,
    body: { state: "off", ack: { id: replacement.id, result: "done" } },
    nowMs: nowMs + 3_000,
  });
  assert.equal(duplicate.ack, "duplicate");

  const expired = await enqueueCommand({ store, deviceId, action: "power_on", actor: "owner@example.com", nowMs });
  const missed = await handleDevicePoll({
    store,
    deviceId,
    body: pollBody,
    nowMs: nowMs + COMMAND_TTL_SECONDS * 1000 + 1,
  });
  assert.equal(missed.command, null);
  const view = await readPowerView(store, deviceId, nowMs + COMMAND_TTL_SECONDS * 1000 + 1);
  assert.equal(view.pending, null);
  assert.equal(view.online, true);
  assert.equal(view.heartbeat?.state, "off");
  assert.equal(view.audit.filter((event) => event.kind === "ack").length, 1);
  assert.equal(view.audit.some((event) => event.kind === "expire" && event.commandId === expired.id), true);
  assert.equal(view.audit.some((event) => event.kind === "replace"), true);
  assert.equal(view.audit.some((event) => event.actor === "owner@example.com" && event.detail === first.id), true);
});

test("store TTL hides an unclaimed command and grants are one-shot and action-bound", async () => {
  const store = new MemoryPowerStore();
  let now = 1_000_000;
  store.now = () => now;
  await enqueueCommand({ store, deviceId, action: "power_on", actor: "owner@example.com", nowMs: now });
  now += COMMAND_TTL_SECONDS * 1000 + 1;
  assert.equal(await store.get("power:v1:pending:home-pc"), null);

  const grant = await issueGrant(store, "subject-1", "power_on", deviceId);
  assert.equal(await consumeGrant(store, grant, "subject-1", "power_off", deviceId), false);
  const replacement = await issueGrant(store, "subject-1", "power_on", deviceId);
  assert.equal(await consumeGrant(store, replacement, "subject-1", "power_on", deviceId), true);
  assert.equal(await consumeGrant(store, replacement, "subject-1", "power_on", deviceId), false);
  assert.equal(await consumeGrant(store, grant, "subject-1", "power_on", deviceId), false);
});

test("owner matching and device rate limit fail closed", async () => {
  assert.deepEqual(parseOwnerEmails(" Owner@Example.com, owner@example.com, ops@example.com "), ["owner@example.com", "ops@example.com"]);
  assert.equal(isOwnerEmail("owner@example.com", ["owner@example.com"]), true);
  assert.equal(isOwnerEmail("ops@example.com", ["owner@example.com"]), false);

  const store = new MemoryPowerStore();
  const body = Buffer.from("{}");
  for (let index = 0; index < DEVICE_RATE_LIMIT; index += 1) {
    const nonce = `nonce-value-${String(index).padStart(4, "0")}`;
    await authed(store, signed(body, nonce));
  }
  await assert.rejects(
    () => authed(store, signed(body, "nonce-value-9999")),
    (error: unknown) => error instanceof PowerHttpError && error.status === 429,
  );
});

test("power store credentials stay on Upstash and reject partial configuration", () => {
  assert.equal(assertUpstashUrl("https://example-store.upstash.io").hostname, "example-store.upstash.io");
  assert.throws(() => assertUpstashUrl("https://evil.example/steal"), PowerHttpError);
  assert.throws(() => assertUpstashUrl("http://example.upstash.io"), PowerHttpError);
  assert.deepEqual(
    storeCredentials({ POWER_STORE_REST_URL: " https://example.upstash.io ", POWER_STORE_REST_TOKEN: " token-value-123456 " }),
    { url: "https://example.upstash.io", token: "token-value-123456" },
  );
  assert.throws(
    () => storeCredentials({ POWER_STORE_REST_URL: "https://example.upstash.io" }),
    (error: unknown) => error instanceof PowerHttpError && error.status === 503,
  );
});
