# ESP32 power button

Reference firmware for a home-Wi-Fi ESP32 that polls the Vercel app and momentarily closes a relay across the PC power-switch header. Power-on and power-off are the same short pulse a person would make with the case button. The sketch does not hold the button down for a forced power-off.

## Wiring

- Power the ESP32 from a USB supply that stays on when the PC is off.
- Use a relay module. Connect its dry contacts to the two pins of the motherboard power-switch header. Do not connect an ESP32 GPIO directly across that header.
- `POWER_RELAY_PIN` drives the relay input. Set `POWER_RELAY_ACTIVE_HIGH` to match the module. The pin idles in the released state.
- Optional: wire a 3.3V "PC is on" signal, such as a divided power-LED tap, to `POWER_SENSE_PIN`. Leave the pin at `-1` to report `unknown`. The sense pin must never see 5V or 12V.

## Configuration

```sh
cp firmware/esp32-power/config.example.h firmware/esp32-power/config.h
openssl rand -hex 32
```

Put the Wi-Fi name, Wi-Fi password, Vercel origin, device id, and the same 64-character device secret in `config.h`. `config.h` is gitignored. Paste the PEM of the CA that signs the Vercel hostname into `POWER_CA_PEM`. If the hostname is proxied by Cloudflare, that is the Cloudflare edge CA, not the origin certificate.

Open `firmware/esp32-power/esp32-power.ino` in the Arduino IDE or as a PlatformIO Arduino sketch for an ESP32 board. The sketch needs the ESP32 Arduino core, Wi-Fi, NTP, and the core's mbedTLS headers. No extra libraries are required.

## Protocol

Every 3 seconds the device `POST`s `https://<vercel>/api/power/device/poll` with:

- `X-Power-Device-Id`
- `X-Power-Timestamp` as Unix seconds
- `X-Power-Nonce` as 32 lowercase hex characters
- `X-Power-Signature` as HMAC-SHA256, lowercase hex

The HMAC key is the 32 raw bytes decoded from `POWER_DEVICE_SECRET`. The message is UTF-8:

```text
<timestamp>\n<nonce>\nPOST\n/api/power/device/poll\n<sha256 hex of the raw body>
```

The body is JSON: `state` (`on`, `off`, or `unknown`), `firmware`, and `ack` (`null` or `{id,result}`). The server allows a 60-second clock skew, stores the nonce for 120 seconds, and returns at most one command. A command is removed when it is delivered. A second poll does not receive it again. Commands expire after 30 seconds.

The response is `{"ack":"...","command":null}` or `{"ack":"...","command":{"id":"...","action":"power_on"|"power_off","expiresAt":"..."}}`. The device pulses only for those two actions, skips a pulse when the sense pin already matches the requested state, and sends the result on the next poll.

The ESP32 does not use Cloudflare Access. The Vercel hostname's Access application needs a bypass only for `POST /api/power/device/poll`. Every other path stays behind Access. The device secret is the only credential on that path.
