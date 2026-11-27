import { createHash } from "node:crypto";

export const DEVICE_POLL_PATH = "/api/power/device/poll";
export const COMMAND_TTL_SECONDS = 30;
export const NONCE_TTL_SECONDS = 120;
export const HEARTBEAT_TTL_SECONDS = 90;
export const INFLIGHT_TTL_SECONDS = 180;
export const ACK_TTL_SECONDS = 86_400;
export const GRANT_TTL_SECONDS = 60;
export const CHALLENGE_TTL_SECONDS = 120;
export const CLOCK_SKEW_SECONDS = 60;
export const DEVICE_RATE_LIMIT = 40;
export const OWNER_RATE_LIMIT = 30;
export const AUDIT_LIMIT = 100;
export const MAX_PASSKEYS = 8;

export function subjectHash(subject: string): string {
  return createHash("sha256").update(subject).digest("hex").slice(0, 32);
}

export const powerKeys = {
  nonce: (deviceId: string, nonce: string) => `power:v1:nonce:${deviceId}:${nonce}`,
  pending: (deviceId: string) => `power:v1:pending:${deviceId}`,
  inflight: (deviceId: string) => `power:v1:inflight:${deviceId}`,
  ack: (deviceId: string, commandId: string) => `power:v1:ack:${deviceId}:${commandId}`,
  state: (deviceId: string) => `power:v1:state:${deviceId}`,
  audit: (deviceId: string) => `power:v1:audit:${deviceId}`,
  rate: (bucket: string) => `power:v1:rate:${bucket}`,
  grant: (token: string) => `power:v1:grant:${token}`,
  challenge: (id: string) => `power:v1:challenge:${id}`,
  passkey: (id: string) => `power:v1:passkey:${id}`,
  passkeyIndex: (subject: string) => `power:v1:passkeys:${subjectHash(subject)}`,
};
