#!/usr/bin/env python3
"""Independent check: decode the base URL from apktool smali (not jadx), and confirm the
path strings and auth header names exist in the smali."""
import re, sys
D = "decompiled/apktool/smali/com/fieldnotes/demo/"
ok = True
def res(c, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + c); ok &= bool(cond)
e = open(D + "Endpoints.smali").read()
arr = re.search(r"\.array-data 4\n(.*?)\.end array-data", e, re.S).group(1)
vals = [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", arr)]
key = int(re.search(r"KEY:I = (0x[0-9a-f]+)", e).group(1), 16)
base = "".join(chr(v ^ key) for v in vals)
res("base url decodes to https://api.fieldnotes.example", base == "https://api.fieldnotes.example")
res("session path literal", '"/v2/session"' in e)
res("sync path literal", '"/v2/notes/sync"' in e)
res("diagnostics path is reversed literal", '"gaid/lanretni/"' in e and "gaid/lanretni/"[::-1] == "/internal/diag")
a = open(D + "ApiClient.smali").read()
res("Authorization Bearer header", '"Authorization"' in a and '"Bearer "' in a)
res("X-App-Key header", '"X-App-Key"' in a)
res("session response parsed for token", '"token":' in a.replace('\\"', '"'))
sys.exit(0 if ok else 1)
