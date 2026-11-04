/* Benchmark 3: a harmless telemetry agent. It reads settings from its own registry key and sends
   one frame to a listener on this machine. It installs nothing and collects nothing personal. */
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REGISTRY_KEY "Software\\ReKitBench\\Telemetry"
#define DEFAULT_DEVICE "bench-device"
#define AGENT_HOST "127.0.0.1"
#define AGENT_PORT 47800
#define FRAME_MAGIC 0x4C544B52u /* "RKTL" */
#define FRAME_VERSION 2
#define FRAME_HEARTBEAT 1

#pragma pack(push, 1)
struct frame_header {
    uint32_t magic;
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint32_t sequence;
};
#pragma pack(pop)

static void read_device_id(char *device, DWORD size) {
    HKEY key;
    DWORD type = REG_SZ;
    strncpy(device, DEFAULT_DEVICE, size - 1);
    device[size - 1] = '\0';
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return;
    }
    RegQueryValueExA(key, "DeviceId", NULL, &type, (LPBYTE)device, &size);
    RegCloseKey(key);
}

static DWORD read_interval(void) {
    HKEY key;
    DWORD interval = 60;
    DWORD size = sizeof(interval);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, KEY_READ, &key) == ERROR_SUCCESS) {
        RegQueryValueExA(key, "IntervalSeconds", NULL, NULL, (LPBYTE)&interval, &size);
        RegCloseKey(key);
    }
    return interval;
}

static uint16_t checksum(const uint8_t *data, size_t length) {
    uint16_t sum = 0;
    for (size_t index = 0; index < length; index++) {
        sum = (uint16_t)(((sum << 1) | (sum >> 15)) ^ data[index]);
    }
    return sum;
}

static size_t build_frame(uint8_t *frame, size_t capacity, uint32_t sequence, const char *payload) {
    struct frame_header header;
    size_t length = strlen(payload);
    uint16_t sum;
    if (sizeof(header) + length + sizeof(sum) > capacity) {
        return 0;
    }
    header.magic = FRAME_MAGIC;
    header.version = FRAME_VERSION;
    header.type = FRAME_HEARTBEAT;
    header.length = (uint16_t)length;
    header.sequence = sequence;
    memcpy(frame, &header, sizeof(header));
    memcpy(frame + sizeof(header), payload, length);
    sum = checksum(frame, sizeof(header) + length);
    memcpy(frame + sizeof(header) + length, &sum, sizeof(sum));
    return sizeof(header) + length + sizeof(sum);
}

int main(void) {
    char device[64];
    char payload[128];
    uint8_t frame[256];
    size_t size;
    WSADATA winsock;
    SOCKET connection;
    struct sockaddr_in listener;

    read_device_id(device, sizeof(device));
    snprintf(payload, sizeof(payload), "device=%s;uptime=%lu;interval=%lu", device,
             (unsigned long)GetTickCount(), (unsigned long)read_interval());
    size = build_frame(frame, sizeof(frame), 1, payload);

    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        return 1;
    }
    connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    listener.sin_family = AF_INET;
    listener.sin_port = htons(AGENT_PORT);
    listener.sin_addr.s_addr = inet_addr(AGENT_HOST);
    if (connect(connection, (struct sockaddr *)&listener, sizeof(listener)) == 0) {
        send(connection, (const char *)frame, (int)size, 0);
    }
    closesocket(connection);
    WSACleanup();
    return 0;
}
