#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>
#include <mbedtls/md.h>
#include "config.h"

namespace {
constexpr char kPath[] = "/api/power/device/poll";
constexpr unsigned long kPollMs = 3000;
constexpr unsigned long kPulseGapMs = 5000;
constexpr int kFirmwareVersion = 1;

char lastCommandId[80] = "";
unsigned long lastPulseMs = 0;

bool hexToBytes(const char* hex, uint8_t* out, size_t outLen) {
  if (strlen(hex) != outLen * 2) return false;
  for (size_t i = 0; i < outLen; ++i) {
    char pair[3] = {hex[i * 2], hex[i * 2 + 1], 0};
    char* end = nullptr;
    long value = strtol(pair, &end, 16);
    if (end != pair + 2 || value < 0) return false;
    out[i] = static_cast<uint8_t>(value);
  }
  return true;
}

void bytesToHex(const uint8_t* in, size_t len, char* out) {
  static const char* digits = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out[i * 2] = digits[in[i] >> 4];
    out[i * 2 + 1] = digits[in[i] & 0x0f];
  }
  out[len * 2] = 0;
}

bool sha256(const uint8_t* input, size_t length, uint8_t out[32]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info && mbedtls_md(info, input, length, out) == 0;
}

bool hmacSha256(const uint8_t* key, size_t keyLen, const char* message, uint8_t out[32]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info && mbedtls_md_hmac(info, key, keyLen, reinterpret_cast<const unsigned char*>(message), strlen(message), out) == 0;
}

bool timeReady() {
  return time(nullptr) > 1700000000;
}

const char* reportedState() {
#if POWER_SENSE_PIN < 0
  return "unknown";
#else
  return digitalRead(POWER_SENSE_PIN) == HIGH ? "on" : "off";
#endif
}

void pulseButton() {
  unsigned long now = millis();
  if (now - lastPulseMs < kPulseGapMs) return;
  lastPulseMs = now;
  digitalWrite(POWER_RELAY_PIN, POWER_RELAY_ACTIVE_HIGH ? HIGH : LOW);
  delay(POWER_PULSE_MS);
  digitalWrite(POWER_RELAY_PIN, POWER_RELAY_ACTIVE_HIGH ? LOW : HIGH);
}

bool extractJsonString(const String& body, const char* key, char* out, size_t outLen) {
  String marker = String("\"") + key + "\":\"";
  int start = body.indexOf(marker);
  if (start < 0) return false;
  start += marker.length();
  int end = body.indexOf('"', start);
  if (end < 0 || end - start <= 0 || static_cast<size_t>(end - start) >= outLen) return false;
  body.substring(start, end).toCharArray(out, outLen);
  return true;
}

void setText(char* dest, size_t destLen, const char* value) {
  if (destLen == 0) return;
  strncpy(dest, value, destLen - 1);
  dest[destLen - 1] = 0;
}

void applyCommand(const String& body, char* ackId, size_t ackIdLen, char* ackResult, size_t ackResultLen) {
  setText(ackId, ackIdLen, "");
  setText(ackResult, ackResultLen, "ignored");
  int command = body.indexOf("\"command\":");
  if (command < 0) return;
  String rest = body.substring(command + 10);
  if (rest.startsWith("null")) return;
  char id[80] = "";
  char action[16] = "";
  char expiresAt[40] = "";
  if (!extractJsonString(rest, "id", id, sizeof(id)) || !extractJsonString(rest, "action", action, sizeof(action))) {
    setText(ackResult, ackResultLen, "failed");
    return;
  }
  if (strcmp(id, lastCommandId) == 0) {
    setText(ackId, ackIdLen, id);
    setText(ackResult, ackResultLen, "rejected");
    return;
  }
  extractJsonString(rest, "expiresAt", expiresAt, sizeof(expiresAt));
  setText(lastCommandId, sizeof(lastCommandId), id);
  setText(ackId, ackIdLen, id);
  const char* state = reportedState();
  bool turnOn = strcmp(action, "power_on") == 0;
  bool turnOff = strcmp(action, "power_off") == 0;
  if (!turnOn && !turnOff) {
    setText(ackResult, ackResultLen, "rejected");
    return;
  }
  if ((turnOn && strcmp(state, "on") == 0) || (turnOff && strcmp(state, "off") == 0)) {
    setText(ackResult, ackResultLen, "rejected");
    return;
  }
  if (timeReady() && expiresAt[0]) {
    struct tm parsed {};
    if (strptime(expiresAt, "%Y-%m-%dT%H:%M:%S", &parsed)) {
      time_t expires = timegm(&parsed);
      if (expires > 0 && time(nullptr) > expires) {
        setText(ackResult, ackResultLen, "rejected");
        return;
      }
    }
  }
  pulseButton();
  setText(ackResult, ackResultLen, "done");
}

String buildBody(const char* ackId, const char* ackResult) {
  String body = String("{\"state\":\"") + reportedState() + "\",\"firmware\":\"esp32-power-" + kFirmwareVersion + "\",\"ack\":";
  if (!ackId[0] || strcmp(ackResult, "ignored") == 0) body += "null";
  else body += String("{\"id\":\"") + ackId + "\",\"result\":\"" + ackResult + "\"}";
  body += "}";
  return body;
}
}

void setup() {
  pinMode(POWER_RELAY_PIN, OUTPUT);
  digitalWrite(POWER_RELAY_PIN, POWER_RELAY_ACTIVE_HIGH ? LOW : HIGH);
#if POWER_SENSE_PIN >= 0
  pinMode(POWER_SENSE_PIN, INPUT);
#endif
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
}

void loop() {
  static char pendingAckId[80] = "";
  static char pendingAckResult[16] = "ignored";
  if (WiFi.status() != WL_CONNECTED || !timeReady()) {
    delay(kPollMs);
    return;
  }
  uint8_t key[32];
  if (!hexToBytes(POWER_DEVICE_SECRET, key, sizeof(key)) || !strstr(POWER_CA_PEM, "BEGIN CERTIFICATE")) {
    delay(kPollMs);
    return;
  }

  String body = buildBody(pendingAckId, pendingAckResult);
  uint8_t hash[32];
  char hashHex[65];
  if (!sha256(reinterpret_cast<const uint8_t*>(body.c_str()), body.length(), hash)) {
    delay(kPollMs);
    return;
  }
  bytesToHex(hash, sizeof(hash), hashHex);
  char nonceHex[33];
  uint8_t nonce[16];
  for (size_t i = 0; i < sizeof(nonce); i += 4) {
    uint32_t value = esp_random();
    memcpy(nonce + i, &value, 4);
  }
  bytesToHex(nonce, sizeof(nonce), nonceHex);
  String timestamp = String(static_cast<uint32_t>(time(nullptr)));
  String message = timestamp + "\n" + nonceHex + "\nPOST\n" + kPath + "\n" + hashHex;
  uint8_t mac[32];
  char signature[65];
  if (!hmacSha256(key, sizeof(key), message.c_str(), mac)) {
    delay(kPollMs);
    return;
  }
  bytesToHex(mac, sizeof(mac), signature);

  WiFiClientSecure client;
  client.setCACert(POWER_CA_PEM);
  HTTPClient http;
  if (!http.begin(client, String(POWER_BASE_URL) + kPath)) {
    delay(kPollMs);
    return;
  }
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Power-Device-Id", POWER_DEVICE_ID);
  http.addHeader("X-Power-Timestamp", timestamp);
  http.addHeader("X-Power-Nonce", nonceHex);
  http.addHeader("X-Power-Signature", signature);
  int status = http.POST(body);
  String response = status > 0 ? http.getString() : "";
  http.end();
  if (status == 200) {
    pendingAckId[0] = 0;
    strncpy(pendingAckResult, "ignored", sizeof(pendingAckResult));
    applyCommand(response, pendingAckId, sizeof(pendingAckId), pendingAckResult, sizeof(pendingAckResult));
  }
  delay(kPollMs);
}
