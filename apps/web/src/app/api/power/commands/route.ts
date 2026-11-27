import { assertBrowserOrigin, requireOwner } from "@/lib/power/access";
import { assertOwnerRate, consumeGrant, enqueueCommand } from "@/lib/power/commands";
import { requireDevice } from "@/lib/power/env";
import { PowerHttpError } from "@/lib/power/errors";
import { json, powerError, readJson } from "@/lib/power/http";
import { powerStore } from "@/lib/power/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 15;

export async function POST(request: Request) {
  try {
    assertBrowserOrigin(request);
    const identity = await requireOwner(request);
    const store = powerStore();
    await assertOwnerRate(store, identity.subject, "write");
    const body = await readJson(request, 1_024);
    const action = body.action;
    if (action !== "power_on" && action !== "power_off") throw new PowerHttpError(400, "Invalid power action");
    if (typeof body.reauthGrant !== "string") throw new PowerHttpError(403, "Reauthentication required");
    const device = requireDevice();
    const allowed = await consumeGrant(store, body.reauthGrant, identity.subject, action, device.deviceId);
    if (!allowed) throw new PowerHttpError(403, "Reauthentication required");
    const command = await enqueueCommand({
      store,
      deviceId: device.deviceId,
      action,
      actor: identity.email,
    });
    return json({ command });
  } catch (error) {
    return powerError(error);
  }
}
