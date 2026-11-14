import { z } from "zod";
import {
  AuditEventSchema,
  JobRequestSchema,
  JobSchema,
  ContainerLogsSchema,
  ContainerStatsSchema,
  OverviewSchema,
  PasskeyStatusSchema,
  ReauthOptionsSchema,
  RegistrationOptionsSchema,
  ReauthGrantSchema,
  RegistrationResultSchema,
  ResourceSchema,
  type JobRequest,
  type DnsRecordChange,
} from "@/lib/contracts";

async function request<T>(path: string, schema: z.ZodType<T>, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/${path}`, {
    ...init,
    cache: "no-store",
    headers: { Accept: "application/json", ...init?.headers },
  });
  const body: unknown = await response.json().catch(() => null);

  if (!response.ok) {
    const detail = z.object({ detail: z.string().optional(), error: z.string().optional() }).safeParse(body);
    throw new Error(detail.success ? detail.data.detail ?? detail.data.error ?? `API ${response.status}` : `API ${response.status}`);
  }

  if (response.status === 204) return undefined as T;

  return schema.parse(body);
}

export const getOverview = (signal?: AbortSignal) =>
  request("v1/metrics/overview", OverviewSchema, { signal });

export const getResource = (key: string, signal?: AbortSignal) =>
  request(`v1/resources/${encodeURIComponent(key)}`, ResourceSchema, { signal });

export const getJobs = (signal?: AbortSignal, limit = 50) =>
  request(`v1/jobs?limit=${limit}`, z.array(JobSchema), { signal });

export const getAudit = (signal?: AbortSignal, limit = 100) =>
  request(`v1/audit?limit=${limit}`, z.array(AuditEventSchema), { signal });

export const getContainerLogs = (containerId: string, signal?: AbortSignal) =>
  request(`v1/containers/${encodeURIComponent(containerId)}/logs?tail=200`, ContainerLogsSchema, { signal });

export const getContainerStats = (containerId: string, signal?: AbortSignal) =>
  request(`v1/containers/${encodeURIComponent(containerId)}/stats`, ContainerStatsSchema, { signal });

export const createJob = (input: JobRequest) => {
  const body = JobRequestSchema.parse(input);
  return request("v1/jobs", JobSchema, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
};

const postJson = <T>(path: string, schema: z.ZodType<T>, payload: unknown) =>
  request(path, schema, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

export const getPasskeyStatus = (signal?: AbortSignal) =>
  request("v1/webauthn/status", PasskeyStatusSchema, { signal });

export const beginPasskeyReauth = (input: {
  operation: "register_passkey" | "delete_passkey" | "start" | "stop" | "restart" | "dns_create" | "dns_update" | "dns_delete";
  target: string;
  dnsChange?: DnsRecordChange;
}) =>
  postJson("v1/webauthn/reauth/options", ReauthOptionsSchema, input);

export const finishPasskeyReauth = (input: { challengeId: string; credential: unknown }) =>
  postJson("v1/webauthn/reauth/verify", ReauthGrantSchema, input);

export const beginPasskeyRegistration = (input: { name: string; bootstrapToken?: string; reauthGrant?: string }) =>
  postJson("v1/webauthn/register/options", RegistrationOptionsSchema, input);

export const finishPasskeyRegistration = (input: { challengeId: string; credential: unknown }) =>
  postJson("v1/webauthn/register/verify", RegistrationResultSchema, input);

export const removePasskey = (input: { credentialId: string; reauthGrant: string }) =>
  postJson("v1/webauthn/passkeys/delete", z.undefined(), input);

