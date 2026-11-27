import { createHash } from "node:crypto";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { PowerHttpError } from "./errors.ts";
import { CHALLENGE_TTL_SECONDS, MAX_PASSKEYS, powerKeys } from "./keys.ts";
import { bootstrapMatches, consumeGrant, issueGrant, recordAudit } from "./commands.ts";
import type { PowerStore } from "./store.ts";

const transports = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,256}$/;

export type StoredPasskey = {
  id: string;
  publicKey: string;
  counter: number;
  transports: AuthenticatorTransportFuture[];
  subject: string;
  name: string;
  createdAt: string;
};

type ChallengeRecord = {
  subject: string;
  purpose: "register" | "reauth";
  operation: string;
  target: string;
  challenge: string;
  name?: string;
};

export async function listPasskeys(store: PowerStore, subject: string): Promise<StoredPasskey[]> {
  const ids = parseIndex(await store.get(powerKeys.passkeyIndex(subject)));
  const passkeys: StoredPasskey[] = [];
  for (const id of ids) {
    const passkey = parsePasskey(await store.get(powerKeys.passkey(id)));
    if (passkey?.subject === subject) passkeys.push(passkey);
  }
  return passkeys;
}

export async function beginRegistration(input: {
  store: PowerStore;
  subject: string;
  email: string;
  name: string;
  rpId: string;
  rpName: string;
  bootstrapToken?: string;
  reauthGrant?: string;
  expectedBootstrap: string | null;
}): Promise<{ challengeId: string; options: unknown }> {
  const name = cleanName(input.name);
  const existing = await listPasskeys(input.store, input.subject);
  if (existing.length >= MAX_PASSKEYS) throw new PowerHttpError(409, "Passkey limit reached");
  if (existing.length === 0) {
    if (!input.expectedBootstrap || !input.bootstrapToken || !bootstrapMatches(input.bootstrapToken, input.expectedBootstrap)) {
      throw new PowerHttpError(403, "Passkey enrollment token required");
    }
  } else {
    const allowed = input.reauthGrant
      ? await consumeGrant(input.store, input.reauthGrant, input.subject, "register_passkey", "account")
      : false;
    if (!allowed) throw new PowerHttpError(403, "Reauthentication required");
  }
  const options = await generateRegistrationOptions({
    rpName: input.rpName,
    rpID: input.rpId,
    userName: input.email,
    userID: createHash("sha256").update(input.subject).digest(),
    attestationType: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    excludeCredentials: existing.map((passkey) => ({ id: passkey.id, transports: passkey.transports })),
    timeout: CHALLENGE_TTL_SECONDS * 1000,
  });
  const challengeId = crypto.randomUUID();
  await saveChallenge(input.store, challengeId, {
    subject: input.subject,
    purpose: "register",
    operation: "register_passkey",
    target: "account",
    challenge: options.challenge,
    name,
  });
  return { challengeId, options };
}

export async function finishRegistration(input: {
  store: PowerStore;
  subject: string;
  email: string;
  deviceId: string;
  challengeId: string;
  credential: unknown;
  origin: string;
  rpId: string;
}): Promise<void> {
  const challenge = await takeChallenge(input.store, input.challengeId, input.subject, "register");
  const verification = await verifyRegistrationResponse({
    response: asRegistration(input.credential),
    expectedChallenge: challenge.challenge,
    expectedOrigin: input.origin,
    expectedRPID: input.rpId,
    requireUserVerification: true,
  }).catch(() => {
    throw new PowerHttpError(401, "Passkey verification failed");
  });
  if (!verification.verified) throw new PowerHttpError(401, "Passkey verification failed");
  const created = verification.registrationInfo.credential;
  if (!CREDENTIAL_ID.test(created.id)) throw new PowerHttpError(400, "Invalid passkey");
  const record: StoredPasskey = {
    id: created.id,
    publicKey: isoBase64URL.fromBuffer(created.publicKey),
    counter: created.counter,
    transports: (created.transports ?? []).filter((item): item is AuthenticatorTransportFuture => transports.has(item)),
    subject: input.subject,
    name: challenge.name || "Passkey",
    createdAt: new Date().toISOString(),
  };
  const saved = await input.store.set(powerKeys.passkey(record.id), JSON.stringify(record), { nx: true });
  if (saved !== "OK") throw new PowerHttpError(409, "Passkey already registered");
  const ids = parseIndex(await input.store.get(powerKeys.passkeyIndex(input.subject)));
  ids.push(record.id);
  await input.store.set(powerKeys.passkeyIndex(input.subject), JSON.stringify(ids.slice(-MAX_PASSKEYS)));
  await recordAudit(input.store, input.deviceId, { actor: input.email, kind: "enroll", detail: record.name });
}

export async function beginReauthentication(input: {
  store: PowerStore;
  subject: string;
  operation: string;
  target: string;
  rpId: string;
}): Promise<{ challengeId: string; options: unknown }> {
  if (!["power_on", "power_off", "register_passkey", "delete_passkey"].includes(input.operation)) {
    throw new PowerHttpError(400, "Invalid reauthentication operation");
  }
  const credentials = await listPasskeys(input.store, input.subject);
  if (!credentials.length) throw new PowerHttpError(409, "Passkey setup required");
  if (input.operation === "register_passkey" && input.target !== "account") {
    throw new PowerHttpError(400, "Invalid reauthentication scope");
  }
  if (input.operation === "delete_passkey" && !credentials.some((item) => item.id === input.target)) {
    throw new PowerHttpError(404, "Passkey not found");
  }
  const options = await generateAuthenticationOptions({
    rpID: input.rpId,
    allowCredentials: credentials.map((passkey) => ({ id: passkey.id, transports: passkey.transports })),
    userVerification: "required",
    timeout: CHALLENGE_TTL_SECONDS * 1000,
  });
  const challengeId = crypto.randomUUID();
  await saveChallenge(input.store, challengeId, {
    subject: input.subject,
    purpose: "reauth",
    operation: input.operation,
    target: input.target,
    challenge: options.challenge,
  });
  return { challengeId, options };
}

export async function finishReauthentication(input: {
  store: PowerStore;
  subject: string;
  challengeId: string;
  credential: unknown;
  origin: string;
  rpId: string;
}): Promise<{ grant: string; operation: string; target: string }> {
  const challenge = await takeChallenge(input.store, input.challengeId, input.subject, "reauth");
  const response = asAuthentication(input.credential);
  const passkey = parsePasskey(await input.store.get(powerKeys.passkey(response.id)));
  if (!passkey || passkey.subject !== input.subject) throw new PowerHttpError(401, "Passkey verification failed");
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: challenge.challenge,
    expectedOrigin: input.origin,
    expectedRPID: input.rpId,
    requireUserVerification: true,
    credential: {
      id: passkey.id,
      publicKey: isoBase64URL.toBuffer(passkey.publicKey),
      counter: passkey.counter,
      transports: passkey.transports,
    },
  }).catch(() => {
    throw new PowerHttpError(401, "Passkey verification failed");
  });
  if (!verification.verified || !verification.authenticationInfo.userVerified) {
    throw new PowerHttpError(401, "Passkey verification failed");
  }
  passkey.counter = verification.authenticationInfo.newCounter;
  await input.store.set(powerKeys.passkey(passkey.id), JSON.stringify(passkey));
  const grant = await issueGrant(input.store, input.subject, challenge.operation, challenge.target);
  return { grant, operation: challenge.operation, target: challenge.target };
}

export async function deletePasskey(input: {
  store: PowerStore;
  subject: string;
  email: string;
  deviceId: string;
  credentialId: string;
  reauthGrant: string;
}): Promise<void> {
  if (!CREDENTIAL_ID.test(input.credentialId)) throw new PowerHttpError(404, "Passkey not found");
  const allowed = await consumeGrant(input.store, input.reauthGrant, input.subject, "delete_passkey", input.credentialId);
  if (!allowed) throw new PowerHttpError(403, "Reauthentication required");
  const passkey = parsePasskey(await input.store.get(powerKeys.passkey(input.credentialId)));
  if (!passkey || passkey.subject !== input.subject) throw new PowerHttpError(404, "Passkey not found");
  await input.store.getDel(powerKeys.passkey(input.credentialId));
  const ids = parseIndex(await input.store.get(powerKeys.passkeyIndex(input.subject))).filter((id) => id !== input.credentialId);
  await input.store.set(powerKeys.passkeyIndex(input.subject), JSON.stringify(ids));
  await recordAudit(input.store, input.deviceId, { actor: input.email, kind: "remove", detail: passkey.name });
}

async function saveChallenge(store: PowerStore, id: string, record: ChallengeRecord): Promise<void> {
  await store.set(powerKeys.challenge(id), JSON.stringify(record), { ttlSeconds: CHALLENGE_TTL_SECONDS });
}

async function takeChallenge(store: PowerStore, id: string, subject: string, purpose: ChallengeRecord["purpose"]): Promise<ChallengeRecord> {
  if (!/^[0-9a-f-]{36}$/.test(id)) throw new PowerHttpError(400, "Invalid challenge");
  const raw = await store.getDel(powerKeys.challenge(id));
  const record = raw ? parseChallenge(raw) : null;
  if (!record || record.subject !== subject || record.purpose !== purpose) {
    throw new PowerHttpError(400, "Challenge expired");
  }
  return record;
}

function parseChallenge(raw: string): ChallengeRecord | null {
  try {
    const value = JSON.parse(raw) as Partial<ChallengeRecord>;
    if (!value || (value.purpose !== "register" && value.purpose !== "reauth")) return null;
    if (typeof value.subject !== "string" || typeof value.operation !== "string" || typeof value.target !== "string" || typeof value.challenge !== "string") return null;
    return value as ChallengeRecord;
  } catch {
    return null;
  }
}

function parsePasskey(raw: string | null): StoredPasskey | null {
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as Partial<StoredPasskey>;
    if (!value || typeof value.id !== "string" || !CREDENTIAL_ID.test(value.id)) return null;
    if (typeof value.publicKey !== "string" || typeof value.subject !== "string" || typeof value.name !== "string") return null;
    if (typeof value.counter !== "number" || typeof value.createdAt !== "string") return null;
    const parsedTransports = Array.isArray(value.transports)
      ? value.transports.filter((item): item is AuthenticatorTransportFuture => typeof item === "string" && transports.has(item))
      : [];
    return { ...value, transports: parsedTransports } as StoredPasskey;
  } catch {
    return null;
  }
}

function parseIndex(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const value = JSON.parse(raw) as unknown;
    if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !CREDENTIAL_ID.test(item))) return [];
    return value;
  } catch {
    return [];
  }
}

export function cleanName(value: string): string {
  const name = value.trim();
  if (name.length < 1 || name.length > 40 || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new PowerHttpError(400, "Invalid passkey name");
  }
  return name;
}

function asRegistration(value: unknown): RegistrationResponseJSON {
  if (!value || typeof value !== "object") throw new PowerHttpError(400, "Invalid passkey");
  return value as RegistrationResponseJSON;
}

function asAuthentication(value: unknown): AuthenticationResponseJSON {
  if (!value || typeof value !== "object" || !("id" in value) || typeof value.id !== "string") {
    throw new PowerHttpError(400, "Invalid passkey");
  }
  return value as AuthenticationResponseJSON;
}
