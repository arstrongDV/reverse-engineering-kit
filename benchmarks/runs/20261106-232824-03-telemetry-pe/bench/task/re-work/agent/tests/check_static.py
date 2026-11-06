import struct, sys
b = open("original/agent.exe", "rb").read()
bad = 0
def chk(name, ok):
    global bad
    print(("PASS " if ok else "FAIL ") + name); bad += not ok
chk("registry key string", b"Software\\ReKitBench\\Telemetry\0" in b)
chk("DeviceId value", b"DeviceId\0" in b)
chk("IntervalSeconds value", b"IntervalSeconds\0" in b)
chk("payload format", b"device=%s;uptime=%lu;interval=%lu\0" in b)
chk("loopback addr", b"127.0.0.1\0" in b)
chk("port 0xbab8=47800 htons imm", struct.pack("<I", 0xbab8) in b or struct.pack("<H", 0xbab8) in b)
sys.exit(1 if bad else 0)
