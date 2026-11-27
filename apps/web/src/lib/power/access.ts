import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import { PowerHttpError } from "./errors.ts";

export type AccessIdentity = { subject: string; email: string };

const jwksCache = new Map<string, JWTVerifyGetKey>();

export function parseOwnerEmails(value: string): string[] {
  return [...new Set(value.split(",").map((item) => item.trim().toLowerCase()).filter(Boolean))];
}

export function isOwnerEmail(email: string, owners: readonly string[]): boolean {
  return owners.includes(email.trim().toLowerCase());
}

export function devAuthEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.POWER_DEV_AUTH !== "1") return false;
  if (env.VERCEL || env.VERCEL_ENV) return false;
  return true;
}

export function accessSettings(env: NodeJS.ProcessEnv = process.env): { issuer: string; audiences: string[]; jwksUrl: string } | null {
  const issuerValue = env.CF_ACCESS_ISSUER?.trim() ?? "";
  const audienceValue = env.CF_ACCESS_AUD?.trim() ?? "";
  if (!issuerValue || !audienceValue) return null;
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuerValue);
  } catch {
    return null;
  }
  if (
    issuerUrl.protocol !== "https:"
    || issuerUrl.username
    || issuerUrl.password
    || issuerUrl.search
    || issuerUrl.hash
    || (issuerUrl.pathname !== "/" && issuerUrl.pathname !== "")
    || issuerValue.replace(/\/$/, "") !== issuerUrl.origin
  ) return null;
  const audiences = audienceValue.split(",").map((item) => item.trim());
  if (
    audiences.length < 1
    || audiences.length > 4
    || audiences.some((item) => !/^[A-Za-z0-9._-]{1,200}$/.test(item))
  ) return null;
  const configuredJwks = env.CF_ACCESS_JWKS_URL?.trim() ?? "";
  const jwksUrl = configuredJwks || `${issuerUrl.origin}/cdn-cgi/access/certs`;
  try {
    const jwks = new URL(jwksUrl);
    if (jwks.origin !== issuerUrl.origin || jwks.pathname !== "/cdn-cgi/access/certs" || jwks.search || jwks.hash) return null;
  } catch {
    return null;
  }
  return { issuer: issuerUrl.origin, audiences, jwksUrl };
}

export async function verifyAccessJwt(token: string, settings: { issuer: string; audiences: string[]; jwksUrl: string }): Promise<AccessIdentity> {
  if (token.length < 20 || token.length > 8_192) throw new PowerHttpError(401, "Invalid Access assertion");
  let jwks = jwksCache.get(settings.jwksUrl);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(settings.jwksUrl));
    jwksCache.set(settings.jwksUrl, jwks);
  }
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: settings.issuer,
      audience: settings.audiences,
      algorithms: ["RS256"],
      clockTolerance: 30,
      requiredClaims: ["exp", "iss", "aud", "sub"],
    });
    const email = payload.email;
    if (!payload.sub || typeof email !== "string" || !email.includes("@") || email.length > 254) {
      throw new Error("invalid identity");
    }
    return { subject: payload.sub, email: email.trim().toLowerCase() };
  } catch (error) {
    if (error instanceof PowerHttpError) throw error;
    throw new PowerHttpError(401, "Invalid Access assertion");
  }
}

export function accessTokenFrom(request: Request): string | null {
  const header = request.headers.get("cf-access-jwt-assertion")?.trim();
  if (header) return header;
  const cookie = request.headers.get("cookie");
  if (!cookie) return null;
  for (const part of cookie.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === "CF_Authorization" && rest.length) {
      try {
        return decodeURIComponent(rest.join("=")).trim() || null;
      } catch {
        return null;
      }
    }
  }
  return null;
}

export async function authenticateBrowser(request: Request, env: NodeJS.ProcessEnv = process.env): Promise<AccessIdentity> {
  if (devAuthEnabled(env)) return { subject: "local-development", email: "local@development.invalid" };
  const token = accessTokenFrom(request);
  if (!token) throw new PowerHttpError(401, "Access assertion required");
  const settings = accessSettings(env);
  if (!settings) throw new PowerHttpError(503, "Access verification is not configured");
  return verifyAccessJwt(token, settings);
}

export function ownerAllowlist(env: NodeJS.ProcessEnv = process.env): string[] {
  const configured = parseOwnerEmails(env.POWER_OWNER_EMAILS ?? "");
  if (configured.length === 0) {
    if (devAuthEnabled(env)) return ["local@development.invalid"];
    throw new PowerHttpError(503, "Power owners are not configured");
  }
  if (
    configured.length > 10
    || configured.some((email) => email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(email))
  ) {
    throw new PowerHttpError(503, "Power owners are not configured");
  }
  return configured;
}

export async function requireOwner(request: Request, env: NodeJS.ProcessEnv = process.env): Promise<AccessIdentity> {
  const identity = await authenticateBrowser(request, env);
  if (!isOwnerEmail(identity.email, ownerAllowlist(env))) throw new PowerHttpError(403, "Owner role required");
  return identity;
}

export function expectedOrigin(request: Request, env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.WEB_ORIGIN?.trim() ?? "";
  if (configured) {
    const url = parseOrigin(configured);
    if (!url) throw new PowerHttpError(503, "Web origin is not configured");
    return url.origin;
  }
  if (!devAuthEnabled(env)) throw new PowerHttpError(503, "Web origin is not configured");
  const requestOrigin = request.headers.get("origin");
  const url = requestOrigin ? parseOrigin(requestOrigin) : null;
  if (!url || url.protocol !== "http:" || !["localhost", "127.0.0.1", "::1"].includes(url.hostname)) {
    throw new PowerHttpError(403, "Origin check failed");
  }
  return url.origin;
}

export function assertBrowserOrigin(request: Request, env: NodeJS.ProcessEnv = process.env): string {
  const origin = request.headers.get("origin");
  const expected = expectedOrigin(request, env);
  if (!origin || origin !== expected) throw new PowerHttpError(403, "Origin check failed");
  return expected;
}

export function relyingParty(origin: string, env: NodeJS.ProcessEnv = process.env): { rpId: string; rpName: string; origin: string } {
  const hostname = new URL(origin).hostname.toLowerCase();
  const rpId = (env.POWER_RP_ID?.trim() || hostname).toLowerCase();
  const rpName = (env.POWER_RP_NAME?.trim() || "HomeServer Admin");
  if (!/^[a-z0-9.-]{1,253}$/.test(rpId) || rpId.includes("..") || rpName.length < 1 || rpName.length > 64) {
    throw new PowerHttpError(503, "Power relying party is not configured");
  }
  return { rpId, rpName, origin };
}

function parseOrigin(value: string): URL | null {
  try {
    const url = new URL(value);
    const local = url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
    if (
      (url.protocol !== "https:" && !local)
      || url.username
      || url.password
      || url.search
      || url.hash
      || (url.pathname !== "/" && url.pathname !== "")
    ) return null;
    if (value !== url.origin) return null;
    return url;
  } catch {
    return null;
  }
}
