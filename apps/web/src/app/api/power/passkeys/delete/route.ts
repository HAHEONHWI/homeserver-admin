import { assertBrowserOrigin, requireOwner } from "@/lib/power/access";
import { assertOwnerRate } from "@/lib/power/commands";
import { deviceSettings } from "@/lib/power/env";
import { powerError, readJson } from "@/lib/power/http";
import { deletePasskey } from "@/lib/power/passkeys";
import { powerStore } from "@/lib/power/store";
import { PowerHttpError } from "@/lib/power/errors";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 15;

export async function POST(request: Request) {
  try {
    assertBrowserOrigin(request);
    const identity = await requireOwner(request);
    const store = powerStore();
    await assertOwnerRate(store, identity.subject, "write");
    const body = await readJson(request, 2_048);
    if (typeof body.credentialId !== "string" || typeof body.reauthGrant !== "string") {
      throw new PowerHttpError(400, "Invalid request");
    }
    const device = deviceSettings();
    await deletePasskey({
      store,
      subject: identity.subject,
      email: identity.email,
      deviceId: device?.deviceId ?? "home-pc",
      credentialId: body.credentialId,
      reauthGrant: body.reauthGrant,
    });
    return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    return powerError(error);
  }
}
