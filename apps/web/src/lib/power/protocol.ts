import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { PowerHttpError } from "./errors.ts";
import { CLOCK_SKEW_SECONDS, DEVICE_POLL_PATH, DEVICE_RATE_LIMIT, NONCE_TTL_SECONDS, powerKeys } from "./keys.ts";
import type { PowerStore } from "./store.ts";

const NONCE = /^[A-Za-z0-9_-]{16,64}$/;
const TIMESTAMP = /^[1-9][0-9]{9}$/;
const SIGNATURE = /^[0-9a-f]{64}$/;

export function canonicalDeviceMessage(timestamp: string, nonce: string, method: string, path: string, body: Uint8Array): string {
  const bodyHash = createHash("sha256").update(body).digest("hex");
  return `${timestamp}\n${nonce}\n${method}\n${path}\n${bodyHash}`;
}

export function signDeviceRequest(secret: Uint8Array, timestamp: string, nonce: string, body: Uint8Array, path = DEVICE_POLL_PATH): string {
  const message = canonicalDeviceMessage(timestamp, nonce, "POST", path, body);
  return createHmac("sha256", secret).update(message).digest("hex");
}

export async function authenticateDevice(input: {
  store: PowerStore;
  secret: Uint8Array;
  deviceId: string;
  expectedDeviceId: string;
  timestamp: string;
  nonce: string;
  signature: string;
  body: Uint8Array;
  nowSeconds: number;
}): Promise<void> {
  if (input.deviceId !== input.expectedDeviceId) throw new PowerHttpError(401, "Invalid device signature");
  if (!TIMESTAMP.test(input.timestamp) || !NONCE.test(input.nonce) || !SIGNATURE.test(input.signature)) {
    throw new PowerHttpError(401, "Invalid device signature");
  }
  const skew = Math.abs(input.nowSeconds - Number(input.timestamp));
  if (skew > CLOCK_SKEW_SECONDS) throw new PowerHttpError(401, "Stale device request");
  const expected = signDeviceRequest(input.secret, input.timestamp, input.nonce, input.body);
  if (!safeEqualHex(expected, input.signature)) throw new PowerHttpError(401, "Invalid device signature");
  const nonceStored = await input.store.set(
    powerKeys.nonce(input.expectedDeviceId, input.nonce),
    "1",
    { ttlSeconds: NONCE_TTL_SECONDS, nx: true },
  );
  if (nonceStored !== "OK") throw new PowerHttpError(401, "Replay rejected");
  const hits = await input.store.increment(powerKeys.rate(`device:${input.expectedDeviceId}`), 60);
  if (hits > DEVICE_RATE_LIMIT) throw new PowerHttpError(429, "Device rate limit exceeded");
}

function safeEqualHex(expected: string, actual: string): boolean {
  const left = Buffer.from(expected, "hex");
  const right = Buffer.from(actual, "hex");
  if (left.length !== right.length) {
    timingSafeEqual(left, left);
    return false;
  }
  return timingSafeEqual(left, right);
}
