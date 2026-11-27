import { z } from "zod";
import { ApiError } from "@/lib/api";

const CommandSchema = z.object({
  id: z.string(),
  action: z.enum(["power_on", "power_off"]),
  expiresAt: z.string(),
});

export const PowerStatusSchema = z.object({
  configured: z.boolean(),
  deviceId: z.string().nullable(),
  device: z.object({
    online: z.boolean(),
    state: z.enum(["on", "off", "unknown", "offline"]),
    firmware: z.string(),
    seenAt: z.string().nullable(),
  }),
  pending: CommandSchema.nullable(),
  inflight: CommandSchema.nullable(),
  audit: z.array(z.object({
    id: z.string(),
    at: z.string(),
    actor: z.string(),
    kind: z.string(),
    action: z.enum(["power_on", "power_off"]).optional(),
    commandId: z.string().optional(),
    result: z.enum(["done", "rejected", "failed"]).optional(),
    detail: z.string().optional(),
  })),
  passkeys: z.array(z.object({ id: z.string(), name: z.string(), createdAt: z.string() })),
  bootstrapRequired: z.boolean(),
  commandTtlSeconds: z.number(),
});

export const PowerChallengeSchema = z.object({
  challengeId: z.string(),
  options: z.unknown(),
});

export const PowerGrantSchema = z.object({ grant: z.string() });
export type PowerStatus = z.infer<typeof PowerStatusSchema>;
export type PowerPasskey = PowerStatus["passkeys"][number];

async function powerRequest<T>(path: string, schema: z.ZodType<T>, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/power/${path}`, {
    ...init,
    cache: "no-store",
    headers: { Accept: "application/json", ...init?.headers },
  });
  if (response.status === 204) return undefined as T;
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = z.object({ detail: z.string().optional() }).safeParse(body);
    throw new ApiError(response.status, detail.success ? detail.data.detail ?? `API ${response.status}` : `API ${response.status}`);
  }
  return schema.parse(body);
}

const postJson = <T>(path: string, schema: z.ZodType<T>, payload: unknown) =>
  powerRequest(path, schema, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

export const getPowerStatus = (signal?: AbortSignal) =>
  powerRequest("status", PowerStatusSchema, { signal });

export const beginPowerReauth = (input: { operation: "power_on" | "power_off" | "register_passkey" | "delete_passkey"; target?: string }) =>
  postJson("reauth/options", PowerChallengeSchema, input);

export const finishPowerReauth = (input: { challengeId: string; credential: unknown }) =>
  postJson("reauth/verify", PowerGrantSchema, input);

export const queuePowerCommand = (input: { action: "power_on" | "power_off"; reauthGrant: string }) =>
  postJson("commands", z.object({ command: CommandSchema }), input);

export const beginPowerPasskey = (input: { name: string; bootstrapToken?: string; reauthGrant?: string }) =>
  postJson("passkeys/options", PowerChallengeSchema, input);

export const finishPowerPasskey = (input: { challengeId: string; credential: unknown }) =>
  postJson("passkeys/verify", z.undefined(), input);

export const deletePowerPasskey = (input: { credentialId: string; reauthGrant: string }) =>
  postJson("passkeys/delete", z.undefined(), input);
