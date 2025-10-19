#!/usr/bin/env python3
"""
CovertWatch v2.1 — Passive Covert-Channel Detector
Filename: covertw.py

Lightweight real-time covert-channel detector and analyzer for Kali Linux.
Features: progress-bar live dashboard, entropy/timing analysis, and final report.
"""

import os, sys, re, time, math, shutil, subprocess, json
from datetime import datetime, timezone
from collections import defaultdict
from statistics import mean, stdev

# =========================
# === Terminal Utilities ===
# =========================
class C:
    BOLD="\033[1m"; CYAN="\033[96m"; GREEN="\033[92m"; YELLOW="\033[93m"; RED="\033[91m"; RESET="\033[0m"

def color(s, c): return f"{c}{s}{C.RESET}"

def progress_bar(current, total, length=30):
    pct = min(1.0, max(0.0, current / total))
    filled = int(length * pct)
    bar = "█" * filled + "-" * (length - filled)
    return f"[{bar}] {int(pct * 100):3d}%"

def now_iso(): 
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def banner_anim():
    msg = "Initializing CovertWatch..."
    for i in range(3):
        sys.stdout.write(f"\r{C.CYAN}{msg[:len(msg)//3*(i+1)]}{C.RESET}")
        sys.stdout.flush()
        time.sleep(0.4)
    sys.stdout.write("\r" + " " * len(msg) + "\r")
    sys.stdout.flush()

# =========================
# === Helper Functions  ===
# =========================
def check_tool(name): return shutil.which(name) is not None

def shannon_entropy(data: bytes) -> float:
    if not data: return 0
    freq = {}
    for b in data: freq[b] = freq.get(b, 0)+1
    ent = 0.0
    ln2 = math.log(2)
    l = len(data)
    for v in freq.values():
        p = v/l
        ent -= p*(math.log(p)/ln2)
    return ent

# =========================
# === Live Capture Core ===
# =========================
class PacketEvent:
    def __init__(self, ts, proto, src, dst, length, raw):
        self.ts=ts; self.proto=proto; self.src=src; self.dst=dst; self.length=length; self.raw=raw

class CovertWatch:
    def __init__(self, iface, duration, target=None, bpf=None, save_json=None):
        self.iface=iface; self.duration=duration
        self.target=target; self.bpf=bpf; self.save_json=save_json
        self.events=[]; self.start=time.time()

    def _build_cmd(self):
        cmd=["tcpdump","-l","-n","-s","0","-i",self.iface]
        if self.bpf: cmd+=[self.bpf]
        return cmd

    def _parse(self,line):
        ts=time.time(); proto="IP"; src=dst=""; length=0
        if "ICMP" in line: proto="ICMP"
        elif ".53" in line or "dns" in line.lower(): proto="DNS"
        m_ip=re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})",line)
        if len(m_ip)>=2: src,dst=m_ip[0],m_ip[1]
        m_len=re.search(r"length\s+(\d+)",line)
        if m_len: length=int(m_len.group(1))
        return PacketEvent(ts,proto,src,dst,length,line)

# =========================
# === Analyzer (Stream) ===
# =========================
class Analyzer:
    def __init__(self,events):
        self.events=events
        self.proto_counts=defaultdict(int)
        self.iats=[]
        self.sizes=[]
        self.entropy_hits=0
        self.icmp_lens=defaultdict(list)
        self.last_ts=None
        for e in events:
            self.proto_counts[e.proto]+=1
            if self.last_ts: self.iats.append(e.ts-self.last_ts)
            self.last_ts=e.ts
            if e.length>0: self.sizes.append(e.length)
            if e.proto=="DNS":
                parts=re.findall(r"([A-Za-z0-9\-]+)\.[A-Za-z]{2,}", e.raw)
                for p in parts:
                    if shannon_entropy(p.encode())>4.0: self.entropy_hits+=1
            if e.proto=="ICMP": self.icmp_lens[(e.src,e.dst)].append(e.length)

    def summary(self):
        total=len(self.events)
        mu_iat=mean(self.iats) if self.iats else 0
        sd_iat=stdev(self.iats) if len(self.iats)>1 else 0
        unique_len=len(set(self.sizes)) if self.sizes else 0
        suspicious_icmp=sum(1 for v in self.icmp_lens.values() if len(set(v))<=3 and len(v)>=6)
        return {
            "total": total,
            "proto": dict(self.proto_counts),
            "mean_iat": mu_iat,
            "sd_iat": sd_iat,
            "unique_lengths": unique_len,
            "entropy_hits": self.entropy_hits,
            "suspicious_icmp": suspicious_icmp
        }

# =========================
# === Live Dashboard ===
# =========================
def draw_dashboard(iface, duration, start_ts, events, stats):
    elapsed=time.time()-start_ts
    pct=min(1.0,(elapsed/duration))
    sys.stdout.write("\r")
    sys.stdout.write(color(f"╔═ CovertWatch [{iface}] ══════════════════════════════════════════════════╗\n", C.CYAN))
    sys.stdout.write(f" Duration: {duration}s | Elapsed: {elapsed:.1f}s {progress_bar(elapsed,duration)}\n")
    p=stats["proto"]
    sys.stdout.write(f" Packets: {stats['total']} | IP: {p.get('IP',0)} | DNS: {p.get('DNS',0)} | ICMP: {p.get('ICMP',0)}\n")
    sys.stdout.write(f" Avg IAT: {stats['mean_iat']:.4f}s | Unique Lengths: {stats['unique_lengths']:<4} | Flows: {len(set((e.src,e.dst) for e in events))}\n")
    sys.stdout.write(f" Suspicious Timing: {1 if stats['sd_iat']<0.02 and stats['total']>10 else 0} | High-Entropy DNS: {stats['entropy_hits']} | Suspicious ICMP: {stats['suspicious_icmp']}\n")
    sys.stdout.write(f" Last Update: {now_iso()}\n")
    sys.stdout.write(color("╚════════════════════════════════════════════════════════════════════════╝", C.CYAN))
    sys.stdout.flush()

# =========================
# === Help Display ===
# =========================
HELP_TEXT=f"""
{C.CYAN}╔══════════════════════════════════════════════════════╗{C.RESET}
{C.CYAN}║                  C O V E R T W A T C H               ║{C.RESET}
{C.CYAN}╚══════════════════════════════════════════════════════╝{C.RESET}

Passive Covert-Channel Detector

Usage:
  sudo ./covertw.py --iface wlan0 --duration 60
  sudo ./covertw.py --iface eth0 --duration 120 --target 10.0.0.5
  ./covertw.py --help

Options:
  --iface IFACE        Capture interface (required)
  --duration SECS      Capture duration (default 60)
  --target IP          Optional focus on a specific IP
  --bpf FILTER         Optional custom BPF filter string
  --save-json PATH     Optional JSON export
  --help, -h           Show this help
  --version            Show version
"""

# =========================
# === Main Entrypoint ===
# =========================
def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(HELP_TEXT); sys.exit(0)
    if "--version" in sys.argv:
        print("CovertWatch v2.1 — Kali Edition"); sys.exit(0)

    args=sys.argv[1:]
    iface=None; duration=60; target=None; bpf=None; save_json=None
    i=0
    while i<len(args):
        a=args[i]
        if a=="--iface": i+=1; iface=args[i]
        elif a=="--duration": i+=1; duration=int(args[i])
        elif a=="--target": i+=1; target=args[i]
        elif a=="--bpf": i+=1; bpf=args[i]
        elif a=="--save-json": i+=1; save_json=args[i]
        i+=1

    if not iface:
        print(color("[X] Missing required --iface", C.RED)); sys.exit(2)
    if os.geteuid()!=0:
        print(color("[!] Run as root for best results", C.YELLOW))

    banner_anim()
    cw=CovertWatch(iface,duration,target,bpf,save_json)

    if not check_tool("tcpdump"):
        print(color("[X] tcpdump not found.", C.RED)); sys.exit(2)

    try:
        proc=subprocess.Popen(cw._build_cmd(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    except Exception as e:
        print(color(f"[X] Failed to start tcpdump: {e}",C.RED)); sys.exit(1)

    start=time.time()
    while time.time()-start<cw.duration:
        line=proc.stdout.readline()
        if not line:
            if proc.poll() is not None: break
            continue
        ev=cw._parse(line)
        if ev:
            if not cw.target or ev.src==cw.target or ev.dst==cw.target:
                cw.events.append(ev)
        stats=Analyzer(cw.events).summary()
        draw_dashboard(iface,cw.duration,cw.start,cw.events,stats)
        time.sleep(1)

    try: proc.terminate()
    except: pass

    stats=Analyzer(cw.events).summary()
    print("\n"+color("[+] Capture complete. Generating final report...\n",C.GREEN))
    time.sleep(1)

    print(color("╔═══════════════ Final Summary ═══════════════╗",C.CYAN))
    print(color(f"Captured: {stats['total']} packets",C.CYAN))
    for k,v in stats["proto"].items():
        print(f"  {k}: {v}")
    print(f"Unique lengths: {stats['unique_lengths']}, High-entropy DNS: {stats['entropy_hits']}, Suspicious ICMP: {stats['suspicious_icmp']}")
    if stats["sd_iat"]<0.02 and stats["total"]>10:
        print(color("[!] Potential timing-channel detected",C.YELLOW))
    if stats["entropy_hits"]>0:
        print(color("[!] Possible encoded DNS activity",C.YELLOW))
    if stats["suspicious_icmp"]>0:
        print(color("[!] ICMP signaling anomalies",C.YELLOW))
    print(color("╚═════════════════════════════════════════════╝",C.CYAN))

    if save_json:
        try:
            with open(save_json,"w") as f: json.dump(stats,f,indent=2)
            print(color(f"[+] JSON saved to {save_json}",C.GREEN))
        except Exception as e: print(color(f"[!] Failed to save JSON: {e}",C.YELLOW))

    print(color("[+] CovertWatch complete.",C.GREEN))

if __name__=="__main__":
    main()
