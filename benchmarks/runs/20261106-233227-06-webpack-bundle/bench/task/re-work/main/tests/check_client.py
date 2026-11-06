import json, subprocess, sys
fails = 0
for sc in ["ok", "expired"]:
    out = {}
    for w in ["orig", "model"]:
        r = subprocess.run(["node", "tests/harness.js", w, sc], capture_output=True, text=True, timeout=30)
        out[w] = json.loads(r.stdout.strip().splitlines()[-1]) if r.returncode == 0 and r.stdout.strip() else r.stderr
    same = out["orig"] == out["model"] and isinstance(out["orig"], dict)
    print(("PASS" if same else "FAIL"), sc, json.dumps(out["orig"])[:300])
    fails += not same
# literal-URL case: the original really requests the documented endpoints
o = subprocess.run(["node", "tests/harness.js", "orig", "ok"], capture_output=True, text=True).stdout
urls = [c["url"] for c in json.loads(o)["calls"]]
want = ["https://shop.example/api/v3/auth/login", "https://shop.example/api/v3/orders?limit=50", "https://shop.example/api/v3/orders/7/cancel"]
ok = urls == want
print("PASS" if ok else "FAIL", "endpoints", urls); fails += not ok
sys.exit(1 if fails else 0)
