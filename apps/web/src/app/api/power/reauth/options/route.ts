import { assertBrowserOrigin, requireOwner, relyingParty } from "@/lib/power/access";
import { assertOwnerRate } from "@/lib/power/commands";
import { requireDevice } from "@/lib/power/env";
import { json, powerError, readJson } from "@/lib/power/http";
import { beginReauthentication } from "@/lib/power/passkeys";
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
    const body = await readJson(request, 1_024);
    const operation = body.operation;
    if (typeof operation !== "string") throw new PowerHttpError(400, "Invalid reauthentication operation");
    const device = requireDevice();
    const target = operation === "power_on" || operation === "power_off"
      ? device.deviceId
      : typeof body.target === "string" ? body.target : "";
    const party = relyingParty(origin);
    return json(await beginReauthentication({
      store,
      subject: identity.subject,
      operation,
      target,
      rpId: party.rpId,
    }));
  } catch (error) {
    return powerError(error);
  }
}
