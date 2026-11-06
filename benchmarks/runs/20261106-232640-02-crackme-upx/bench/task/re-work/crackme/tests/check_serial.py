import subprocess, sys
T = "original/crackme-packed"
CASES = {"RK26-XOR7-ROL3-A": True, "RK26-XOR7-ROL3-B": False, "short": False}
bad = 0
for a, exp in CASES.items():
    r = subprocess.run([T, a], capture_output=True, text=True)
    ok = (r.returncode == 0 and "Correct" in r.stdout) == exp
    bad += not ok
    print(("PASS" if ok else "FAIL"), repr(a))
sys.exit(1 if bad else 0)
