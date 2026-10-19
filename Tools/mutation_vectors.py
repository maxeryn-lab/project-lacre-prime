import subprocess, shutil, sys
muts = [
 ("lacre-core/src/session.rs", 'b"lacre-core/v1/session-key"', 'b"lacre-core/v1/session-kex"', "HKDF info"),
 ("lacre-core/src/core.rs", 'b"lacre-core/v1/initial-state"', 'b"lacre-core/v1/initial-statf"', "contexto Es(0)"),
 ("lacre-core/src/core.rs", "mac.update(&self.0);\n        mac.update(fragment);", "mac.update(fragment);\n        mac.update(&self.0);", "orden en Es(i+1)"),
 ("lacre-core/src/receipt.rs", "hasher.update(seal.0);", "hasher.update(&seal.0[1..]);", "recibo"),
 ("lacre-domain/src/capability.rs", 'b"lacre-domain/v1/capability"', 'b"lacre-domain/v2/capability"', "dominio capacidad"),
 ("lacre-domain/src/capability.rs", "mac.update(&[0]);\n        mac.update(scope.label());", "mac.update(scope.label());", "separador cero capacidad"),
]
pkgs = {"lacre-core":"lacre-core","lacre-domain":"lacre-domain"}
res=[]
for f,a,b,name in muts:
    s=open(f).read(); assert a in s,(f,a)
    open(f,"w").write(s.replace(a,b,1))
    try:
        pk=f.split('/')[0]
        r=subprocess.run(["cargo","test","-p",pk,"--test","wire_vectors"],capture_output=True,text=True,timeout=280)
        killed = r.returncode!=0
    finally:
        open(f,"w").write(s)
    res.append((name,killed)); print(("MUERTO " if killed else "SUPERVIVIENTE "),name,flush=True)
print(sum(k for _,k in res),"/",len(res))
