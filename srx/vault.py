#!/usr/bin/env python3
"""
vault.py — Persistent Ephemeral Vault Manager (secure + isolated)

Features:
---------
• Create/manage encrypted vaults (AES-GCM + PBKDF2-HMAC-SHA512)
• Decrypted sessions mount in RAM (/dev/shm)
• Optional secure modes: --secure firejail or --secure podman
• Clean ANSI header shows vault name, RAM mount, and status
• Persistent vault repository: ~/.vault/<name>
"""

from __future__ import annotations
import argparse
import base64
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from getpass import getpass
from typing import Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ---------- Configuration ----------
VAULT_REPO = os.path.expanduser("~/.vault")
META_FILENAME = "vaultmeta.json"
SALT_LEN = 16
KEY_LEN = 32
PBKDF2_ITERS = 200_000
AES_NONCE_LEN = 12
TMPFS_BASE = "/dev/shm"
WIPES = 3

os.makedirs(VAULT_REPO, exist_ok=True)

# ---------- Utility ----------
def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def _parse_duration(s: str) -> timedelta:
    s = s.strip().lower()
    if s.endswith("h"): return timedelta(hours=int(s[:-1]))
    if s.endswith("m"): return timedelta(minutes=int(s[:-1]))
    if s.endswith("s"): return timedelta(seconds=int(s[:-1]))
    return timedelta(minutes=int(s))

def b64enc(b: bytes) -> str: return base64.b64encode(b).decode()
def b64dec(s: str) -> bytes: return base64.b64decode(s.encode())

def human_bytes(n: int) -> str:
    for unit in ("B","KB","MB","GB","TB"):
        if n < 1024: return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"

# ---------- Crypto ----------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS,
        backend=default_backend())
    return kdf.derive(password.encode())

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = os.urandom(AES_NONCE_LEN)
    ct = aes.encrypt(nonce, data, None)
    return nonce + ct

def aes_decrypt(blob: bytes, key: bytes) -> bytes:
    nonce, ct = blob[:AES_NONCE_LEN], blob[AES_NONCE_LEN:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)

# ---------- Secure delete ----------
def secure_delete_file(path: str):
    try:
        if not os.path.isfile(path): os.remove(path); return
        size = os.path.getsize(path)
        with open(path, "ba+", buffering=0) as f:
            for _ in range(WIPES):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                try: os.fsync(f.fileno())
                except Exception: pass
        os.remove(path)
    except Exception:
        try: os.remove(path)
        except Exception: pass

def secure_delete_tree(path: str):
    if not os.path.exists(path): return
    for root, dirs, files in os.walk(path, topdown=False):
        for f in files: secure_delete_file(os.path.join(root,f))
        for d in dirs:
            try: os.rmdir(os.path.join(root,d))
            except Exception: pass
    try: os.rmdir(path)
    except Exception: pass

# ---------- Metadata ----------
def _vault_path(name:str)->str: return os.path.join(VAULT_REPO,name)
def _meta_file(name:str)->str: return os.path.join(_vault_path(name),META_FILENAME)

@dataclass
class VaultMeta:
    name: str
    created: str
    salt_b64: str
    expiry: Optional[str]=None
    persistent_mount: bool=False

    @staticmethod
    def load(name:str)->"VaultMeta":
        return VaultMeta(**json.load(open(_meta_file(name))))
    def save(self): json.dump(self.__dict__, open(_meta_file(self.name),"w"), indent=2)

# ---------- Vault operations ----------
def create_vault(name:str, expiry:Optional[str]):
    path=_vault_path(name)
    if os.path.exists(path): print("[!] Vault exists."); sys.exit(1)
    os.makedirs(path)
    salt=os.urandom(SALT_LEN)
    pw=getpass("Set vault password: ")
    _=derive_key(pw,salt)
    meta=VaultMeta(name,_now_iso(),b64enc(salt),
        (datetime.utcnow()+_parse_duration(expiry)).isoformat()+"Z" if expiry else None)
    meta.save()
    print(f"[+] Vault '{name}' created at {path}")
    if meta.expiry: print(f"    Expires: {meta.expiry}")

def add_file(name:str,src:str):
    meta=VaultMeta.load(name)
    key=derive_key(getpass("Vault password: "),b64dec(meta.salt_b64))
    if not os.path.exists(src): print("[!] File not found.");return
    blob=aes_encrypt(open(src,"rb").read(),key)
    dst=os.path.join(_vault_path(name),os.path.basename(src)+".enc")
    open(dst,"wb").write(blob)
    os.chmod(dst,stat.S_IRUSR|stat.S_IWUSR)
    print(f"[+] Encrypted: {os.path.basename(src)}")

def list_vaults():
    for n in sorted(os.listdir(VAULT_REPO)):
        p=_vault_path(n)
        if os.path.isdir(p) and os.path.exists(_meta_file(n)):
            try:
                m=VaultMeta.load(n)
                print(f"- {n}  created:{m.created}  status:{'persisted' if m.persistent_mount else 'idle'}")
            except: pass

def list_contents(name:str):
    p=_vault_path(name)
    if not os.path.exists(p): print("[!] Vault not found.");return
    m=VaultMeta.load(name)
    print(f"Vault {name} — Created {m.created}")
    if m.expiry: print(f"Expires: {m.expiry}")
    for f in sorted(os.listdir(p)):
        if f.endswith(".enc"): print("  ",f)

def _tmpfs_dir(name:str)->str:
    base=TMPFS_BASE if os.path.isdir(TMPFS_BASE) and os.access(TMPFS_BASE,os.W_OK) else tempfile.gettempdir()
    d=os.path.join(base,f"vault_{name}_{int(time.time())}")
    os.makedirs(d,exist_ok=True); return d

def _decrypted_size(path:str)->int:
    total=0
    for r,_,fs in os.walk(path):
        for f in fs:
            try: total+=os.path.getsize(os.path.join(r,f))
            except: pass
    return total

# ---------- Header ----------
def _print_header(name:str,mode:str,mount:str,size:int,net:str):
    CYAN="\033[36m";Y="\033[33m";B="\033[1m";R="\033[0m"
    line="─"*56
    print(f"{CYAN}{line}{R}")
    print(f"{B}🔐  Vault:{R} {name}")
    print(f"{B}📦  Mode:{R} {mode}")
    print(f"{B}⏰  Started:{R} {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{B}📍  Mount:{R} {mount}")
    print(f"{B}💾  Decrypted size:{R} {human_bytes(size)}")
    print(f"{B}🌐  Network:{R} {net}")
    print(f"{CYAN}{line}{R}")
    print(f"{Y}Type 'exit' to close and wipe data unless persisted.{R}")
    print(f"{CYAN}{line}{R}\n")

# ---------- Session ----------
def _spawn_terminal(cwd:str,name:str):
    _print_header(name,"Normal (host shell)",cwd,_decrypted_size(cwd),"HOST")
    env=os.environ.copy()
    for k in("SSH_AUTH_SOCK","HISTFILE"):env.pop(k,None)
    env["VAULT_PATH"]=cwd;env["PS1"]=f"(vault:{name}) \\u@\\h:\\w$ "
    shell=env.get("SHELL","/bin/bash")
    subprocess.run([shell],cwd=cwd,env=env)

def _spawn_secure(method:str,cwd:str,name:str):
    _print_header(name,f"Secure ({method})",cwd,_decrypted_size(cwd),"OFF")
    env=os.environ.copy()
    for k in("SSH_AUTH_SOCK","HISTFILE"):env.pop(k,None)
    env["VAULT_PATH"]=cwd;env["PS1"]=f"(vault:{name}) \\u@\\h:\\w$ "
    if method=="podman":
        if not shutil.which("podman"):print("[!] Podman not found.");return
        cmd=["podman","run","--rm","-it",
            "--name",f"vault_{name}_{int(time.time())}",
            "--net","none","--cap-drop","ALL",
            "--security-opt","no-new-privileges",
            "--mount",f"type=bind,source={cwd},target=/vault",
            "--workdir","/vault",
            "debian:bookworm-slim","/bin/bash"]
    elif method=="firejail":
        if not shutil.which("firejail"):print("[!] Firejail not found.");return
        cmd=["firejail","--quiet",f"--private={cwd}",
            "--private-tmp","--net=none","--caps.drop=all",
            "--nosound","--shell=/bin/bash"]
    else:print("[!] Invalid mode.");return
    subprocess.run(cmd,env=env)

# ---------- Open / Close / Wipe ----------
def open_vault(name:str,persist=False,secure:Optional[str]=None):
    p=_vault_path(name)
    if not os.path.exists(p): print("[!] Vault not found.");return
    m=VaultMeta.load(name)
    if m.expiry:
        try:
            if datetime.utcnow()>datetime.fromisoformat(m.expiry.replace("Z","")):
                print("[!] Vault expired. Wiping.");wipe_vault(name);return
        except: pass
    key=derive_key(getpass("Vault password: "),b64dec(m.salt_b64))
    tmp=_tmpfs_dir(name)
    for f in [x for x in os.listdir(p) if x.endswith(".enc")]:
        try:
            blob=open(os.path.join(p,f),"rb").read()
            out=os.path.join(tmp,f[:-4])
            open(out,"wb").write(aes_decrypt(blob,key))
            os.chmod(out,stat.S_IRUSR|stat.S_IWUSR)
        except Exception as e: print(f"[!] {f}: {e}")
    print(f"[+] Decrypted vault at {tmp}")
    if secure: _spawn_secure(secure.lower(),tmp,name)
    else: _spawn_terminal(tmp,name)
    if persist:
        open(os.path.join(p,".persist"),"w").write(json.dumps({"mount_dir":tmp,"mounted":_now_iso()}))
        m.persistent_mount=True;m.save()
        print("[*] Persisted mount retained until 'vault close <name>'")
    else:
        print("[*] Session ended; wiping...")
        secure_delete_tree(tmp)

def close_vault(name:str):
    p=_vault_path(name);pf=os.path.join(p,".persist")
    if not os.path.exists(pf): print("[!] No persisted mount.");return
    info=json.load(open(pf));mdir=info.get("mount_dir")
    if mdir and os.path.exists(mdir):
        print(f"[+] Wiping {mdir}");secure_delete_tree(mdir)
    os.remove(pf)
    m=VaultMeta.load(name);m.persistent_mount=False;m.save()
    print("[+] Vault closed.")

def wipe_vault(name:str):
    p=_vault_path(name)
    if not os.path.exists(p): print("[!] Vault not found.");return
    if input("Type DELETE to confirm: ")!="DELETE": print("Aborted.");return
    secure_delete_tree(p);print("[!] Vault wiped.")

# ---------- CLI ----------
def build_parser():
    desc="vault — persistent encrypted vault manager (RAM + sandbox)"
    epi=("Examples:\n"
         "  vault create myvault --expiry 2h\n"
         "  vault add myvault secret.txt\n"
         "  vault open myvault --secure firejail\n"
         "  vault open myvault --secure podman --persist\n"
         "  vault list\n"
         "  vault close myvault\n")
    p=argparse.ArgumentParser(description=desc,epilog=epi,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub=p.add_subparsers(dest="cmd",required=True)
    c=sub.add_parser("create");c.add_argument("name");c.add_argument("--expiry")
    a=sub.add_parser("add");a.add_argument("name");a.add_argument("file")
    l=sub.add_parser("list");l.add_argument("name",nargs="?")
    o=sub.add_parser("open");o.add_argument("name")
    o.add_argument("--persist",action="store_true")
    o.add_argument("--secure",choices=["firejail","podman"])
    cl=sub.add_parser("close");cl.add_argument("name")
    w=sub.add_parser("wipe");w.add_argument("name")
    return p

def main():
    p=build_parser();a=p.parse_args()
    if a.cmd=="create":create_vault(a.name,a.expiry)
    elif a.cmd=="add":add_file(a.name,a.file)
    elif a.cmd=="list":list_contents(a.name) if a.name else list_vaults()
    elif a.cmd=="open":open_vault(a.name,a.persist,a.secure)
    elif a.cmd=="close":close_vault(a.name)
    elif a.cmd=="wipe":wipe_vault(a.name)
    else:p.print_help()

if __name__=="__main__":
    main()
