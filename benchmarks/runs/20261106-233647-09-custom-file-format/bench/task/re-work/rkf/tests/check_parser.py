import sys, zlib, importlib.util
sys.dont_write_bytecode = True
sys.path.insert(0, "/tmp/ks")
from kaitaistruct import KaitaiStream
import io
from rkf import Rkf
bad = 0
exp = {"alpha": (2, ["alpha", 1024]), "bravo": (2, ["bravo", bytes(range(32)), -7, "конец"]), "charlie": (3, [b"", "", 2147483647])}
for n, (ver, vals) in exp.items():
    d = open(f"original/{n}.rkf", "rb").read()
    r = Rkf(KaitaiStream(io.BytesIO(d)))
    got = []
    for x in r.records:
        b = getattr(x, "body", None)
        got.append(b.value if hasattr(b, "value") else x.body)
    ok = r.version == ver and got == vals and r.crc32 == zlib.crc32(d[:-4]) and r._io.is_eof()
    print(("PASS" if ok else "FAIL"), n, got)
    bad += not ok
sys.exit(bool(bad))
