import { assertBrowserOrigin, requireOwner, relyingParty } from "@/lib/power/access";
import { assertOwnerRate } from "@/lib/power/commands";
import { deviceSettings } from "@/lib/power/env";
import { powerError, readJson } from "@/lib/power/http";
import { finishRegistration } from "@/lib/power/passkeys";
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
    const body = await readJson(request, 16_384);
    if (typeof body.challengeId !== "string") throw new PowerHttpError(400, "Invalid challenge");
    const party = relyingParty(origin);
    const device = deviceSettings();
    await finishRegistration({
      store,
      subject: identity.subject,
      email: identity.email,
      deviceId: device?.deviceId ?? "home-pc",
      challengeId: body.challengeId,
      credential: body.credential,
      origin,
      rpId: party.rpId,
    });
    return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    return powerError(error);
  }
}
