#!/usr/bin/env python3
"""
PackNet — Interactive Packet Forge & Replay
Author: quicksilver
"""

from __future__ import annotations
import argparse
import cmd
import os
import readline
import shlex
import socket
import sys
import time
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional

try:
    from scapy.all import (
        Ether, IP, IPv6, TCP, UDP, ICMP, Raw,
        send, sendp, hexdump, wrpcap, rdpcap, conf
    )
except Exception:
    sys.stderr.write("ERROR: scapy is required. Install via:\n  sudo apt install python3-scapy\n")
    sys.exit(1)

HOME = os.path.expanduser("~")
PACKNET_DIR = os.path.join(HOME, ".packnet")
LOG_DIR = os.path.join(PACKNET_DIR, "logs")
PCAP_DIR = os.path.join(PACKNET_DIR, "pcaps")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(PCAP_DIR, exist_ok=True)

def now_ts(): return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def write_log(msg: str):
    f = os.path.join(LOG_DIR, f"packnet-{datetime.utcnow().strftime('%Y%m%d')}.log")
    with open(f, "a") as h: h.write(f"{now_ts()} {msg}\n")

def find_iface():
    try:
        if conf.iface: return conf.iface
    except Exception: pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        for name, iface in conf.ifaces.items():
            if getattr(iface, "ip", None) == ip:
                return name
    except Exception: pass
    return "eth0"

@dataclass
class StoredPacket:
    id: int
    pkt: object
    created: str = field(default_factory=now_ts)
    note: str = ""

def ascii_header(title: str):
    line = "═" * 72
    print(f"\n\033[36m{line}\033[0m")
    print(f"  \033[1m{title}\033[0m")
    print(f"  Started: {now_ts()} (UTC)")
    print(f"\033[36m{line}\033[0m\n")

def visualize_packet(pkt):
    from scapy.all import Raw
    layers = []
    p = pkt
    while p:
        layers.append(p)
        p = p.payload
        if isinstance(p, Raw): break

    ascii_header("Packet Visualization")
    for i, layer in enumerate(layers):
        lname = layer.__class__.__name__
        print(f"[{i+1}] Layer: {lname}")
        for k, v in layer.fields.items():
            print(f"   {k:<10} = {v}")
        print("")
    print("Hexdump:")
    hexdump(pkt)

def build_packet(proto, kwargs):
    src = kwargs.get("src")
    dst = kwargs.get("dst")
    eth_src = kwargs.get("eth_src")
    eth_dst = kwargs.get("eth_dst")
    iface = kwargs.get("iface")

    ip_layer = IP(src=src, dst=dst)
    if ":" in str(src) or ":" in str(dst):
        ip_layer = IPv6(src=src, dst=dst)

    if proto == "tcp":
        tcp = TCP(
            sport=int(kwargs.get("sport", 0)) or None,
            dport=int(kwargs.get("dport", 0)) or None,
            flags=kwargs.get("flags", "")
        )
        payload = kwargs.get("payload")
        pkt = ip_layer / tcp / Raw(load=payload.encode() if payload else b"")
    elif proto == "udp":
        udp = UDP(
            sport=int(kwargs.get("sport", 0)) or None,
            dport=int(kwargs.get("dport", 0)) or None,
        )
        payload = kwargs.get("payload")
        pkt = ip_layer / udp / Raw(load=payload.encode() if payload else b"")
    elif proto == "icmp":
        ic = ICMP()
        payload = kwargs.get("payload")
        pkt = ip_layer / ic / Raw(load=payload.encode()) if payload else ip_layer / ic
    elif proto == "raw":
        payload = kwargs.get("payload", "")
        pkt = Raw(load=payload.encode())
    else:
        raise ValueError("Unsupported protocol")

    if eth_src or eth_dst or (iface and iface.startswith("eth")):
        ether = Ether()
        if eth_src: ether.src = eth_src
        if eth_dst: ether.dst = eth_dst
        pkt = ether / pkt
    return pkt

class PackNetShell(cmd.Cmd):
    intro = "PackNet — interactive packet forge. Type 'help' for commands.\n"
    prompt = "packnet> "

    def __init__(self, iface=None):
        super().__init__()
        self.iface = iface or find_iface()
        self.store: Dict[int, StoredPacket] = {}
        self.next_id = 1
        self.simulate = False
        self.send_enabled = False
        ascii_header("PackNet Interactive")
        print(f"Default interface: {self.iface}")
        print("Commands: new, show, visualize, save, replay, send, enable-send, simulate, list, exit")

    def do_exit(self, _): print("Exiting PackNet."); return True
    def do_quit(self, _): return self.do_exit(_)
    def do_list(self, _):
        if not self.store: print("(no stored packets)"); return
        for i, sp in self.store.items():
            print(f"{i:3d} {sp.pkt.summary()} created:{sp.created}")

    def do_new(self, arg):
        parts = shlex.split(arg)
        if not parts: print("Usage: new <tcp|udp|icmp|raw> [--src IP] [--dst IP] ..."); return
        proto = parts[0].lower()
        opts = {}
        for i in range(1, len(parts)):
            if parts[i].startswith("--") and i+1 < len(parts):
                opts[parts[i][2:]] = parts[i+1]
        try:
            pkt = build_packet(proto, opts)
            pid = self.next_id; self.next_id += 1
            self.store[pid] = StoredPacket(pid, pkt)
            print(f"[+] Packet {pid} created: {pkt.summary()}")
        except Exception as e: print("Error:", e)

    def do_show(self, arg):
        try:
            pid = int(arg.strip())
            sp = self.store.get(pid)
            if not sp: print("Invalid ID"); return
            print(sp.pkt.summary()); hexdump(sp.pkt)
        except Exception: print("Usage: show <id>")

    def do_visualize(self, arg):
        try:
            pid = int(arg.strip())
            sp = self.store.get(pid)
            if not sp: print("Invalid ID"); return
            visualize_packet(sp.pkt)
        except Exception: print("Usage: visualize <id>")

    def do_save(self, arg):
        parts = shlex.split(arg)
        if len(parts) < 3 or parts[1] != "to": print("Usage: save <id> to <file.pcap>"); return
        pid = int(parts[0]); dest = os.path.join(PCAP_DIR, parts[2])
        sp = self.store.get(pid)
        if not sp: print("Invalid ID"); return
        wrpcap(dest, [sp.pkt], append=True)
        print(f"[+] Saved packet {pid} -> {dest}")

    def do_replay(self, arg):
        parts = shlex.split(arg)
        if not parts: print("Usage: replay <file.pcap>"); return
        path = os.path.join(PCAP_DIR, parts[0]) if not os.path.isabs(parts[0]) else parts[0]
        pkts = rdpcap(path)
        print(f"Replaying {len(pkts)} packets...")
        for p in pkts:
            if self.simulate or not self.send_enabled: print(".", end="", flush=True)
            else:
                if p.haslayer(Ether): sendp(p, iface=self.iface, verbose=False)
                else: send(p, iface=self.iface, verbose=False)
            time.sleep(0.05)
        print("\nDone.")

    def do_send(self, arg):
        parts = shlex.split(arg)
        if not parts: print("Usage: send <id> [count N]"); return
        pid = int(parts[0]); sp = self.store.get(pid)
        if not sp: print("Invalid ID"); return
        count = 1
        if "count" in parts: count = int(parts[parts.index("count")+1])
        for _ in range(count):
            if self.simulate or not self.send_enabled:
                print(".", end="", flush=True)
                time.sleep(0.02)
            else:
                try:
                    if sp.pkt.haslayer(Ether): sendp(sp.pkt, iface=self.iface, verbose=False)
                    else: send(sp.pkt, iface=self.iface, verbose=False)
                except PermissionError:
                    print("\nPermission denied (sudo needed)."); break
        print("\n[+] Done.")

    def do_enable_send(self, _):
        if os.geteuid() != 0:
            print("Root required. Run with sudo.")
            return
        if input("Type ENABLE to allow live sends: ") == "ENABLE":
            self.send_enabled = True
            print("[!] Live send enabled for session.")
        else: print("Aborted.")

    def do_simulate(self, arg):
        val = arg.strip().lower()
        if val in ("on", "1"): self.simulate = True; print("Simulate mode ON.")
        elif val in ("off", "0"): self.simulate = False; print("Simulate mode OFF.")
        else: print("Usage: simulate on|off")

# ---------- Main ----------
def show_help():
    ascii_header("PackNet Help — Interactive Packet Forge & Replay")
    print(textwrap.dedent("""
    Usage:
      packnet              Launch interactive shell
      packnet --iface eth0  Specify default interface
      packnet --help        Show this help

    Description:
      PackNet is an advanced, interactive packet forge designed for
      Kali Linux professionals, pentesters, and network engineers.
      It allows safe, real-time crafting, editing, visualization,
      and replay of custom network packets with full ASCII introspection.

    Core Commands:
      new          Create packets (tcp/udp/icmp/raw)
      show         Show summary & hexdump
      visualize    ASCII layer-by-layer breakdown
      list         View stored packets
      save         Save packet to PCAP
      replay       Replay PCAP files
      send         Send crafted packets (requires enable-send)
      simulate     Toggle no-send safety mode
      enable-send  Permit live sends (root required)
      exit         Leave the shell

    Data Storage:
      Logs:  ~/.packnet/logs
      PCAPs: ~/.packnet/pcaps

    Security:
      Live sends are disabled by default. Must use 'enable-send' explicitly.

    Example:
      sudo packnet
      packnet> new tcp --src 10.0.0.2 --dst 10.0.0.3 --dport 80 --flags S
      packnet> visualize 1
      packnet> enable-send
      packnet> send 1
    """))

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--iface", "-i", help="Specify interface")
    parser.add_argument("--help", "-h", action="store_true", help="Show help info and exit")
    args = parser.parse_args()

    if args.help:
        show_help()
        sys.exit(0)

    shell = PackNetShell(iface=args.iface)
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nInterrupted — exiting.")
        write_log("PackNet interrupted")

if __name__ == "__main__":
    main()
