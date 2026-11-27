import { authenticateDevice } from "@/lib/power/protocol";
import { handleDevicePoll } from "@/lib/power/commands";
import { requireDevice } from "@/lib/power/env";
import { assertJson, json, powerError, readBytes } from "@/lib/power/http";
import { powerStore } from "@/lib/power/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 15;

export async function POST(request: Request) {
  try {
    assertJson(request);
    const device = requireDevice();
    const body = await readBytes(request, 4_096);
    const store = powerStore();
    await authenticateDevice({
      store,
      secret: device.secret,
      deviceId: request.headers.get("x-power-device-id")?.trim() ?? "",
      expectedDeviceId: device.deviceId,
      timestamp: request.headers.get("x-power-timestamp")?.trim() ?? "",
      nonce: request.headers.get("x-power-nonce")?.trim() ?? "",
      signature: request.headers.get("x-power-signature")?.trim() ?? "",
      body,
      nowSeconds: Math.floor(Date.now() / 1000),
    });
    const result = await handleDevicePoll({
      store,
      deviceId: device.deviceId,
      body: JSON.parse(new TextDecoder().decode(body)) as unknown,
    });
    return json({
      ack: result.ack,
      command: result.command
        ? { id: result.command.id, action: result.command.action, expiresAt: result.command.expiresAt }
        : null,
    });
  } catch (error) {
    return powerError(error);
  }
}
