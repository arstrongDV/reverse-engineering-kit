import re, sys, subprocess, tempfile, os
# Extract the original asar fresh and compare channels in main.js and preload.js.
d = tempfile.mkdtemp()
subprocess.run(["asar", "extract", "original/app.asar", d], check=True)
main = open(d + "/main.js").read()
pre = open(d + "/preload.js").read()
handled = dict((c, k) for k, c in re.findall(r'ipcMain\.(handle|on)\("([^"]+)"', main)) if False else {c: k for k, c in re.findall(r'ipcMain\.(handle|on)\("([^"]+)"', main)}
used = {c: k for k, c in re.findall(r'ipcRenderer\.(invoke|send)\("([^"]+)"', pre)}
exp = {"notes:list": "handle", "notes:save": "handle", "notes:delete": "handle", "window:minimize": "on", "app:version": "handle"}
ok = True
def case(name, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + name); ok &= bool(cond)
case("main handles exactly the 5 channels", handled == exp)
case("preload uses same channels, invoke<->handle and send<->on", set(used) == set(exp) and all((used[c] == "invoke") == (exp[c] == "handle") for c in used))
case("contextIsolation true, no nodeIntegration", "contextIsolation: true" in main and "nodeIntegration" not in main)
case("negative: no undeclared channel", "ghost:channel" not in handled)
sys.exit(0 if ok else 1)
