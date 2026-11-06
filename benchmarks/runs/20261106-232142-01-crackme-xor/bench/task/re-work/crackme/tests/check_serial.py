import subprocess,sys
E_=bytes.fromhex("404429 45bbdcc2666b772a8eb087d1fe".replace(" ",""))
K=bytes.fromhex("5ac3179e")
ror=lambda b:((b>>3)|(b<<5))&255
s=bytes(ror(e)^K[i%4] for i,e in enumerate(E_)).decode()
print("serial",s)
def run(a):
    return subprocess.run(["original/crackme",a],capture_output=True,text=True).stdout
ok=True
for name,a,want in [("derived",s,"Correct"),("wrong",s[:-1]+"!","Wrong"),("short","abc","Wrong")]:
    r=want in run(a); print(("PASS " if r else "FAIL ")+name); ok&=r
sys.exit(0 if ok else 1)
