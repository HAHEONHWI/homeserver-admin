import { assertBrowserOrigin, requireOwner, relyingParty } from "@/lib/power/access";
import { assertOwnerRate } from "@/lib/power/commands";
import { bootstrapToken } from "@/lib/power/env";
import { json, powerError, readJson } from "@/lib/power/http";
import { beginRegistration, listPasskeys } from "@/lib/power/passkeys";
import { powerStore } from "@/lib/power/store";
import { PowerHttpError } from "@/lib/power/errors";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 15;

export async function POST(request: Request) {
  try {
    const origin = assertBrowserOrigin(request);
    const identity = await requireOwner(request);
    const store = powerStore();
    await assertOwnerRate(store, identity.subject, "write");
    const body = await readJson(request, 2_048);
    if (typeof body.name !== "string") throw new PowerHttpError(400, "Invalid passkey name");
    const existing = await listPasskeys(store, identity.subject);
    const party = relyingParty(origin);
    return json(await beginRegistration({
      store,
      subject: identity.subject,
      email: identity.email,
      name: body.name,
      rpId: party.rpId,
      rpName: party.rpName,
      bootstrapToken: typeof body.bootstrapToken === "string" ? body.bootstrapToken : undefined,
      reauthGrant: typeof body.reauthGrant === "string" ? body.reauthGrant : undefined,
      expectedBootstrap: existing.length === 0 ? bootstrapToken() : null,
    }));
  } catch (error) {
    return powerError(error);
  }
}
