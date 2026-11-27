import { PowerHttpError } from "./errors.ts";
const DEVICE_ID = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;

export function deviceSettings(env: NodeJS.ProcessEnv = process.env): { deviceId: string; secret: Uint8Array } | null {
  const deviceId = (env.POWER_DEVICE_ID?.trim() || "home-pc");
  const secretHex = env.POWER_DEVICE_SECRET?.trim() ?? "";
  if (!secretHex) return null;
  if (!DEVICE_ID.test(deviceId) || !/^[0-9a-f]{64}$/.test(secretHex)) {
    throw new PowerHttpError(503, "Power device is not configured");
  }
  return { deviceId, secret: Buffer.from(secretHex, "hex") };
}

export function requireDevice(env: NodeJS.ProcessEnv = process.env): { deviceId: string; secret: Uint8Array } {
  const device = deviceSettings(env);
  if (!device) throw new PowerHttpError(503, "Power device is not configured");
  return device;
}

export function bootstrapToken(env: NodeJS.ProcessEnv = process.env): string {
  const token = env.POWER_BOOTSTRAP_TOKEN?.trim() ?? "";
  if (!/^[0-9a-f]{64}$/.test(token)) throw new PowerHttpError(503, "Power passkey enrollment is not configured");
  return token;
}
