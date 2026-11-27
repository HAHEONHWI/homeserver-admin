import { assertOwnerRate, readPowerView } from "@/lib/power/commands";
import { COMMAND_TTL_SECONDS } from "@/lib/power/keys";
import { requireOwner } from "@/lib/power/access";
import { deviceSettings } from "@/lib/power/env";
import { json, powerError } from "@/lib/power/http";
import { listPasskeys } from "@/lib/power/passkeys";
import { powerStore } from "@/lib/power/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 15;

export async function GET(request: Request) {
  try {
    const identity = await requireOwner(request);
    const store = powerStore();
    await assertOwnerRate(store, identity.subject, "read");
    const passkeys = await listPasskeys(store, identity.subject);
    const device = deviceSettings();
    const view = device ? await readPowerView(store, device.deviceId) : null;
    return json({
      configured: Boolean(device),
      deviceId: device?.deviceId ?? null,
      device: {
        online: view?.online ?? false,
        state: view?.online && view.heartbeat ? view.heartbeat.state : "offline",
        firmware: view?.heartbeat?.firmware ?? "",
        seenAt: view?.heartbeat?.seenAt ?? null,
      },
      pending: view?.pending ?? null,
      inflight: view?.inflight ?? null,
      audit: view?.audit ?? [],
      passkeys: passkeys.map((passkey) => ({ id: passkey.id, name: passkey.name, createdAt: passkey.createdAt })),
      bootstrapRequired: passkeys.length === 0,
      commandTtlSeconds: COMMAND_TTL_SECONDS,
    });
  } catch (error) {
    return powerError(error);
  }
}
