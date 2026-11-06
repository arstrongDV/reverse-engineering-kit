import ctypes, os, signal, subprocess, sys
B = os.path.abspath("original/antidebug")
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
ok = True
def res(n, c):
    global ok
    print(("PASS " if c else "FAIL ") + n); ok &= bool(c)

out = subprocess.run([B], capture_output=True, text=True).stdout
res("untraced prints launch code", "The launch code is ORCHID-42" in out)

r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.dup2(w, 1); libc.ptrace(0, 0, None, None); os.execv(B, [B])
os.close(w)
os.waitpid(pid, 0)  # exec SIGTRAP stop
libc.ptrace(7, pid, None, None)  # PTRACE_CONT
os.waitpid(pid, 0)
t = os.read(r, 4096).decode()
res("traced prints decoy, no code", "Nothing to see here." in t and "ORCHID" not in t)
# stale first fork (child stopped at exec trap)
try: os.kill(pid_first := 0, 0)
except Exception: pass
sys.exit(0 if ok else 1)
