import { z } from "zod";

const Percent = z.number().finite().min(0).max(100);
const Bytes = z.number().finite().nonnegative();

export const OverviewSchema = z.object({
  mode: z.enum(["mock", "live"]),
  status: z.enum(["connected", "not_configured", "unavailable"]),
  serverName: z.string().min(1),
  updatedAt: z.string().min(1),
  uptimeSeconds: z.number().finite().nonnegative(),
  cpu: z.object({
    percent: Percent,
    cores: z.array(Percent).min(1),
    loadAverage: z.array(z.number().finite()).length(3),
    modelName: z.string().max(256).nullable(),
    physicalCores: z.number().int().positive().nullable(),
    avx2: z.boolean().nullable(),
  }),
  memory: z.object({ usedBytes: Bytes, totalBytes: Bytes, percent: Percent }),
  swap: z.object({ usedBytes: Bytes, totalBytes: Bytes, percent: Percent }),
  storage: z.array(z.object({
    name: z.string().min(1).max(80),
    device: z.string().min(1).max(256),
    mount: z.string().min(1).max(512),
    fileSystem: z.string().min(1).max(32),
    usedBytes: Bytes,
    totalBytes: Bytes.positive(),
    percent: Percent,
    health: z.enum(["healthy", "warning", "not_reported"]),
  })),
  network: z.object({ receivedBytesPerSecond: Bytes, sentBytesPerSecond: Bytes }),
  docker: z.object({
    status: z.enum(["connected", "not_configured", "unavailable"]),
    running: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
    message: z.string(),
  }),
  history: z.array(z.object({ time: z.string(), cpu: Percent, memory: Percent })),
  services: z.array(z.object({
    name: z.string(),
    status: z.enum(["healthy", "warning", "failed", "stopped", "not_configured"]),
    detail: z.string(),
    checkedAt: z.string(),
  })),
  activity: z.array(z.object({
    id: z.string(),
    kind: z.enum(["deployment", "alert", "action", "security"]),
    title: z.string(),
    detail: z.string(),
    createdAt: z.string(),
  })),
});

export const ResourceSchema = z.object({
  key: z.string(),
  mode: z.enum(["mock", "live"]),
  status: z.enum(["connected", "partial", "not_configured", "unavailable"]),
  message: z.string(),
  updatedAt: z.string(),
  metrics: z.array(z.object({ label: z.string(), value: z.string(), detail: z.string() })),
  columns: z.array(z.string()),
  rows: z.array(z.object({
    id: z.string(),
    name: z.string(),
    status: z.string(),
    detail: z.string(),
    updatedAt: z.string(),
    dnsRecord: z.object({
      name: z.string().min(1).max(255),
      type: z.enum(["A", "AAAA", "CNAME", "TXT", "MX"]),
      content: z.string().min(1).max(2048),
      ttl: z.number().int().min(1).max(86400),
      proxied: z.boolean(),
      priority: z.number().int().min(0).max(65535).nullable().optional(),
    }).nullable().optional(),
    actions: z.array(z.object({
      id: z.string(),
      label: z.string(),
      operation: z.enum(["restart", "start", "stop", "backup", "deploy", "rollback", "reboot", "shutdown", "dns_create", "dns_update", "dns_delete"]),
      target: z.string(),
      targetLabel: z.string().max(128).nullable().optional(),
      enabled: z.boolean(),
      reason: z.string(),
    })).default([]),
  })),
  actions: z.array(z.object({
    id: z.string(),
    label: z.string(),
    operation: z.enum(["restart", "start", "stop", "backup", "deploy", "rollback", "reboot", "shutdown", "dns_create", "dns_update", "dns_delete"]),
    target: z.string(),
    targetLabel: z.string().max(128).nullable().optional(),
    enabled: z.boolean(),
    reason: z.string(),
  })),
  writeEnabled: z.boolean().default(false),
});

export const ContainerLogsSchema = z.object({
  mode: z.enum(["mock", "live"]),
  id: z.string(),
  tail: z.number().int().min(1).max(500),
  logs: z.string().max(1_048_576),
  updatedAt: z.string(),
});

export const ContainerStatsSchema = z.object({
  mode: z.enum(["mock", "live"]),
  id: z.string(),
  status: z.enum(["connected", "not_configured", "unavailable"]),
  cpuPercent: z.number().finite().min(0).max(100_000).nullable(),
  memoryUsedBytes: Bytes.nullable(),
  memoryLimitBytes: Bytes.nullable(),
  memoryPercent: Percent.nullable(),
  message: z.string(),
  updatedAt: z.string(),
});

export const JobSchema = z.object({
  id: z.string(),
  operation: z.string(),
  target: z.string(),
  state: z.enum(["queued", "running", "succeeded", "failed", "unknown"]),
  simulation: z.boolean(),
  message: z.string(),
  createdAt: z.string(),
});

export const AuditEventSchema = z.object({
  id: z.string(),
  actor: z.string(),
  operation: z.string(),
  target: z.string(),
  result: z.string(),
  created_at: z.string(),
  details: z.string().default(""),
});

export const DnsRecordValueSchema = z.object({
  name: z.string().min(1).max(255),
  type: z.enum(["A", "AAAA", "CNAME", "TXT", "MX"]),
  content: z.string().min(1).max(2048),
  ttl: z.number().int().min(1).max(86400),
  proxied: z.boolean(),
  priority: z.number().int().min(0).max(65535).nullable().optional(),
});

export const DnsRecordChangeSchema = z.object({
  recordId: z.string().regex(/^[0-9a-fA-F]{32}$/).optional(),
  before: DnsRecordValueSchema.optional(),
  after: DnsRecordValueSchema.optional(),
});

export const JobRequestSchema = z.object({
  operation: z.enum(["restart", "start", "stop", "backup", "deploy", "rollback", "reboot", "shutdown", "dns_create", "dns_update", "dns_delete"]),
  target: z.string().min(1).max(128),
  reauthGrant: z.string().min(32).max(128).optional(),
  dnsChange: DnsRecordChangeSchema.optional(),
}).refine((value) => value.operation.startsWith("dns_") === (value.dnsChange !== undefined), {
  message: "DNS operations require a DNS change payload",
});

export const PasskeySchema = z.object({
  id: z.string().min(1).max(1024),
  name: z.string().min(1).max(64),
  createdAt: z.string().min(1),
});

export const PasskeyStatusSchema = z.object({
  passkeys: z.array(PasskeySchema),
  bootstrapRequired: z.boolean(),
});

const Base64UrlSchema = z.string().min(1).regex(/^[A-Za-z0-9_-]+$/);
const CredentialDescriptorSchema = z.object({
  id: Base64UrlSchema,
  type: z.literal("public-key"),
  transports: z.array(z.string()).optional(),
}).passthrough();

export const ReauthOptionsSchema = z.object({
  challengeId: z.string().min(1),
  options: z.object({
    challenge: Base64UrlSchema,
    rpId: z.string().min(1),
    timeout: z.number().positive(),
    userVerification: z.literal("required"),
    allowCredentials: z.array(CredentialDescriptorSchema).min(1),
  }).passthrough(),
});

export const RegistrationOptionsSchema = z.object({
  challengeId: z.string().min(1),
  options: z.object({
    rp: z.object({ name: z.string().min(1), id: z.string().min(1) }).passthrough(),
    user: z.object({ id: Base64UrlSchema, name: z.string().min(1), displayName: z.string().min(1) }).passthrough(),
    challenge: Base64UrlSchema,
    pubKeyCredParams: z.array(z.object({ type: z.literal("public-key"), alg: z.number().int() }).passthrough()).min(1),
    timeout: z.number().positive(),
    excludeCredentials: z.array(CredentialDescriptorSchema),
    authenticatorSelection: z.object({
      residentKey: z.literal("required"),
      userVerification: z.literal("required"),
      requireResidentKey: z.boolean().optional(),
    }).passthrough(),
  }).passthrough(),
});

export const ReauthGrantSchema = z.object({ grant: z.string().min(32) });
export const RegistrationResultSchema = z.object({ passkey: PasskeySchema });

export type Overview = z.infer<typeof OverviewSchema>;
export type ResourceView = z.infer<typeof ResourceSchema>;
export type ContainerLogs = z.infer<typeof ContainerLogsSchema>;
export type Job = z.infer<typeof JobSchema>;
export type JobRequest = z.infer<typeof JobRequestSchema>;
export type DnsRecordChange = z.infer<typeof DnsRecordChangeSchema>;
export type DnsRecordValue = z.infer<typeof DnsRecordValueSchema>;
export type AuditEvent = z.infer<typeof AuditEventSchema>;
export type PasskeyItem = z.infer<typeof PasskeySchema>;

