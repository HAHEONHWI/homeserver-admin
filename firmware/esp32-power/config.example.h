#pragma once

// Copy this file to config.h and fill in the values. config.h is gitignored.
// Generate the device secret with: openssl rand -hex 32
// Use the same POWER_DEVICE_ID and POWER_DEVICE_SECRET as the Vercel project.

#define WIFI_SSID "your-ssid"
#define WIFI_PASSWORD "your-password"
#define POWER_BASE_URL "https://admin.example.com"
#define POWER_DEVICE_ID "home-pc"
#define POWER_DEVICE_SECRET "replace-with-64-lowercase-hex-characters"

// Dry-contact relay across the motherboard power-switch header.
// 1 drives the pin HIGH to close the relay. 0 drives it LOW.
#define POWER_RELAY_PIN 26
#define POWER_RELAY_ACTIVE_HIGH 1
#define POWER_PULSE_MS 800

// Optional PC-on sense. Use -1 when the pin is not wired.
// The input must be 3.3V logic. HIGH means the PC is on.
#define POWER_SENSE_PIN -1

// PEM for the public CA that signs the Vercel hostname certificate.
// Cloudflare-proxied hostnames present a Cloudflare edge certificate.
// Leave this empty until you paste the current CA. The sketch will not connect without it.
#define POWER_CA_PEM ""
