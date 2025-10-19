#!/usr/bin/env python3
"""
Trace — v1.4r
──────────────────────────────────────────────
Interactive, read-only forensic collector for Kali-like systems.
Includes: local & remote package/drive inspection, network diagnostics,
and detailed local & remote process analysis.

Author: quicksilver (revised)
"""

import os
import sys
import socket
import subprocess
import pwd
import time
import shutil
from datetime import datetime
from pathlib import Path
import argparse
import shlex
import getpass
import signal

# ----------------------------
# Terminal color & helpers
# ----------------------------
class C:
    BOLD = "\033[1m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    RESET = "\033[0m"

def color(text, col): return f"{col}{text}{C.RESET}"

def supports_color():
    return sys.stdout.isatty() and os.environ.get("TERM") not in ("dumb", None)

USE_COLOR = supports_color()

def cprint(txt, col=C.CYAN, end="\n"):
    if USE_COLOR:
        sys.stdout.write(color(txt, col) + end)
    else:
        sys.stdout.write(txt + end)

def safe_exit(code=0):
    try:
        sys.exit(code)
    except SystemExit:
        os._exit(code)

# ----------------------------
# Subprocess runner
# ----------------------------
def run(cmd, timeout=30):
    """Run a command (list or string) and return trimmed stdout/stderr."""
    try:
        if isinstance(cmd, (list, tuple)):
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        else:
            r = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        out = r.stdout.strip()
        if not out and r.stderr:
            out = r.stderr.strip()
        return out or "(no output)"
    except subprocess.TimeoutExpired:
        return "(timeout)"
    except Exception as e:
        return f"(error running {cmd}: {e})"

def safe_read(path, limit=200000):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read(limit)
    except Exception:
        return "(unavailable)"

def get_width():
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80

# ----------------------------
# Banner & Progress UI
# ----------------------------
def banner():
    width = get_width()
    line = "═" * max(10, (width - 2))
    cprint(f"╔{line}╗", C.CYAN)
    cprint(f"║{'T R A C E'.center(width-2)}║", C.CYAN)
    cprint(f"╚{line}╝\n", C.CYAN)

def progress(idx, total, label, status=None):
    width = min(40, max(20, get_width() - 40))
    filled = int((idx / total) * width) if total else width
    bar = "█" * filled + "░" * (width - filled)
    prefix = f"[{idx:02d}/{total:02d}] "
    icon = {
        "ok": color("✅", C.GREEN),
        "warn": color("⚠️", C.YELLOW),
        "fail": color("❌", C.RED),
        None: color("...", C.CYAN)
    }[status]
    sys.stdout.write(f"\r{prefix}[{bar}] {label:<35} {icon}")
    sys.stdout.flush()
    if status in ("ok", "warn", "fail"):
        print("")

# ----------------------------
# SSH helpers for remote runs
# ----------------------------
def build_ssh_command(user, key, port, target, remote_cmd, connect_timeout=6):
    base = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={connect_timeout}", "-p", str(port)]
    if key:
        base.extend(["-i", str(key)])
    base.append(f"{user}@{target}")
    base.append(remote_cmd)
    return base

def run_ssh_capture(user, key, port, target, remote_cmd, timeout=60):
    if not shutil.which("ssh"):
        return "(ssh client not available locally)"
    cmd = build_ssh_command(user, key, port, target, remote_cmd)
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        out = r.stdout.strip()
        if not out and r.stderr:
            out = r.stderr.strip()
        return out or "(no output)"
    except subprocess.TimeoutExpired:
        return "(ssh timeout)"
    except Exception as e:
        return f"(ssh error: {e})"

# ----------------------------
# Local: basic collectors
# ----------------------------
def basic_info():
    time.sleep(0.05)
    cprint("\n=== System Information ===", C.CYAN)
    print(f"Hostname: {socket.gethostname()}")
    print(f"FQDN: {socket.getfqdn()}")
    print(f"Uptime: {run(['uptime', '-p'])}")
    print(f"Kernel: {run(['uname', '-a'])}")
    users = [u.pw_name for u in pwd.getpwall() if (hasattr(u, 'pw_uid') and (u.pw_uid >= 1000 or u.pw_uid == 0))]
    print(f"Users: {', '.join(users)}")

def processes_sample():
    """Lightweight processes summary (top 10)."""
    time.sleep(0.05)
    cprint("\n=== Processes (sample) ===", C.CYAN)
    out = run(["ps", "aux"])
    for i,l in enumerate(out.splitlines()[:10],1):
        print(l)
    if out and len(out.splitlines()) > 10:
        cprint(f"... {len(out.splitlines())-10} more", C.YELLOW)

# ----------------------------
# Local detailed process analysis
# ----------------------------
def local_detailed_processes():
    """Run an in-depth local process analysis (streamlined)."""
    cprint("\n=== Detailed Local Process Analysis ===", C.CYAN)
    if shutil.which("ps"):
        cprint("\n[ps auxf (full process tree)]", C.BOLD)
        print(run(["ps", "auxf"]))
    if shutil.which("pstree"):
        cprint("\n[pstree -a]", C.BOLD)
        print(run(["pstree", "-a"]))
    if shutil.which("top"):
        cprint("\n[top -b -n1]", C.BOLD)
        print(run(["top", "-b", "-n1"])[:15000])
    if shutil.which("lsof"):
        cprint("\n[lsof -i]", C.BOLD)
        print(run(["lsof", "-i"])[:15000])
    cprint("\n[Listening sockets]", C.BOLD)
    if shutil.which("ss"):
        print(run(["ss", "-tunp"]))
    else:
        print(run(["netstat", "-tulpen"]) or "(netstat/ss not available)")
    if shutil.which("ps"):
        cprint("\n[ps -eLf] (threads)", C.BOLD)
        print(run(["ps", "-eLf"])[:20000])

# ----------------------------
# Remote detailed process analysis (no PID enumeration)
# ----------------------------
def remote_detailed_processes_ssh(user, key, port, target):
    """Perform a remote process analysis via SSH (streamlined)."""
    cprint(f"\n=== Remote Detailed Process Analysis for {target} ===", C.CYAN)
    cmds = [
        ("ps auxf", "LANG=C ps auxf"),
        ("pstree -a (if available)",
         "which pstree >/dev/null 2>&1 && pstree -a || echo '(pstree not present)'"),
        ("top snapshot",
         "which top >/dev/null 2>&1 && top -b -n1 || echo '(top not present)'"),
        ("lsof -i",
         "which lsof >/dev/null 2>&1 && lsof -i || echo '(lsof not present)'"),
        ("ss/netstat",
         "which ss >/dev/null 2>&1 && ss -tunp || netstat -tulpen || echo '(ss/netstat not available)'"),
        ("ps -eLf (threads)", "LANG=C ps -eLf || echo '(ps not available)'"),
    ]
    for title, cmd in cmds:
        cprint(f"\n[{title}]", C.BOLD)
        out = run_ssh_capture(user, key, port, target, cmd, timeout=90)
        print(out[:20000])

# ----------------------------
# Network functions (local & remote target diagnostics)
# ----------------------------
def network_local_summary():
    cprint("\n[Interfaces]", C.BOLD); print(run(["ip", "addr"]))
    cprint("\n[Routes]", C.BOLD); print(run(["ip", "route"]))
    cprint("\n[Listening Ports]", C.BOLD); print(run(["ss", "-tunlp"]) or run(["netstat", "-tunlp"]))
    cprint("\n[ARP Table]", C.BOLD); print(run(["arp", "-n"]) or run(["ip", "neigh"]))
    cprint("\n[Recent connections (conntrack)]", C.BOLD)
    print(run(["conntrack", "-L"])[:2000] if shutil.which("conntrack") else "(conntrack not installed)")

def remote_ping(target, count=4):
    cprint(f"\n=== Ping {target} ===", C.CYAN)
    if shutil.which("ping"):
        print(run(["ping", "-c", str(count), target], timeout=20))
    else:
        cprint("(ping not installed)", C.YELLOW)

def remote_traceroute(target):
    cprint(f"\n=== Traceroute to {target} ===", C.CYAN)
    if shutil.which("traceroute"):
        print(run(["traceroute", "-n", target], timeout=90))
    elif shutil.which("tracepath"):
        print(run(["tracepath", target], timeout=90))
    else:
        cprint("(traceroute/tracepath not available)", C.YELLOW)

def remote_reverse_dns(target):
    cprint(f"\n=== Reverse DNS for {target} ===", C.CYAN)
    try:
        addr = socket.gethostbyname(target)
        rev = socket.gethostbyaddr(addr)
        print(f"Resolved {target} -> {addr}; PTR: {rev}")
    except Exception as e:
        if shutil.which("dig"):
            print(run(["dig", "+noall", "+answer", "-x", target]))
        else:
            cprint(f"(reverse lookup failed: {e})", C.YELLOW)

def remote_whois(target):
    cprint(f"\n=== WHOIS for {target} ===", C.CYAN)
    if shutil.which("whois"):
        print(run(["whois", target], timeout=45)[:20000])
    else:
        cprint("(whois not installed)", C.YELLOW)

def remote_nmap(target):
    cprint(f"\n=== Nmap Scan for {target} ===", C.CYAN)
    if not shutil.which("nmap"):
        cprint("(nmap not installed)", C.YELLOW)
        return
    cmd = ["nmap", "-sV", "-Pn", "--reason", "--open", "-T4", target]
    print(run(cmd, timeout=300)[:20000])

def network(target=None):
    time.sleep(0.05)
    cprint("\n=== Network & Sockets ===", C.CYAN)
    network_local_summary()
    if target:
        cprint(f"\n--- Targeted diagnostics for: {target} ---", C.BOLD)
        remote_ping(target)
        remote_traceroute(target)
        remote_reverse_dns(target)
        remote_whois(target)
        remote_nmap(target)

def full_networks(target=None):
    cprint("\n=== Full Network Stack ===", C.CYAN)
    cprint("\n[Interfaces - ip addr]", C.BOLD); print(run(["ip", "addr"]))
    cprint("\n[Routes - ip route]", C.BOLD); print(run(["ip", "route"]))
    cprint("\n[Configured DNS - resolv.conf]", C.BOLD); print(safe_read("/etc/resolv.conf", 10000))
    cprint("\n[Listening Ports - ss -tunlp]", C.BOLD); print(run(["ss", "-tunlp"]) or run(["netstat", "-tunlp"]))
    cprint("\n[ARP table]", C.BOLD); print(run(["arp", "-n"]) or run(["ip", "neigh"]))
    cprint("\n[Wireless info - iwconfig / nmcli dev show]", C.BOLD)
    if shutil.which("iwconfig"):
        print(run(["iwconfig"]))
    if shutil.which("nmcli"):
        print(run(["nmcli", "device", "show"]))
    cprint("\n[iptables -L]", C.BOLD); print(run(["iptables", "-L"]) or "(iptables not available or requires privileges)")
    if target:
        cprint(f"\n--- Performing full remote diagnostics for: {target} ---", C.CYAN)
        remote_ping(target)
        remote_traceroute(target)
        remote_reverse_dns(target)
        remote_whois(target)
        remote_nmap(target)

# ----------------------------
# Packages & drives (local & remote)
# ----------------------------
def packages(sample=True):
    time.sleep(0.05)
    if shutil.which("dpkg"):
        cprint("\n=== Installed Packages ===", C.CYAN)
        dpkg = run(["dpkg", "-l"]).splitlines()
        if sample:
            for l in dpkg[:20]:
                print(l)
            if len(dpkg) > 20:
                cprint(f"... {len(dpkg)-20} more", C.YELLOW)
        else:
            for l in dpkg:
                print(l)
        if shutil.which("apt"):
            cprint("\n[apt list --installed (sample)]", C.BOLD)
            apt = run(["apt", "list", "--installed"]).splitlines()
            if sample:
                for l in apt[:20]: print(l)
            else:
                for l in apt: print(l)
    elif shutil.which("rpm"):
        cprint("\n=== Installed RPM Packages ===", C.CYAN)
        rpm = run(["rpm", "-qa"])
        print(rpm)
    else:
        cprint("\n(No known package manager CLI available)", C.YELLOW)

def full_packages():
    cprint("\n=== Full Installed Packages (verbose) ===", C.CYAN)
    if shutil.which("dpkg"):
        print(run(["dpkg", "-l"]))
    elif shutil.which("rpm"):
        print(run(["rpm", "-qa", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n"]))
    else:
        cprint("(No supported package manager found)", C.YELLOW)
    if shutil.which("apt"):
        cprint("\n[apt policy] (package sources and priorities)", C.BOLD)
        print(run(["apt", "policy"]))
    if shutil.which("apt-get"):
        cprint("\n[apt-get upgrade --simulate] (simulation)", C.BOLD)
        print(run(["apt-get", "-s", "upgrade"])[:20000])

def full_drives():
    cprint("\n=== Full Drives & Block Devices ===", C.CYAN)
    print(run(["lsblk", "-a", "-o", "NAME,FSTYPE,SIZE,MOUNTPOINT,LABEL,UUID,ROTA,MODEL"]))
    cprint("\n[blkid]", C.BOLD)
    print(run(["blkid"]))
    cprint("\n[fdisk -l] (requires root, may show more detailed partition info)", C.BOLD)
    print(run(["fdisk", "-l"]))
    cprint("\n[smartctl -a for all devices] (if smartctl installed)", C.BOLD)
    if shutil.which("smartctl"):
        devs = []
        ls = run(["lsblk", "-ndo", "NAME"]).splitlines()
        for n in ls:
            if n.strip():
                devs.append("/dev/" + n.strip())
        for d in sorted(set(devs)):
            cprint(f"\n[smartctl {d}]", C.BOLD)
            print(run(["smartctl", "-a", d])[:4000])
    else:
        cprint("(smartctl not installed)", C.YELLOW)
    cprint("\n[Mounts & df -h]", C.BOLD)
    print(run(["mount"]))
    print(run(["df", "-h"]))

def remote_full_packages_ssh(user, key, port, target):
    cprint(f"\n=== Remote: Full Installed Packages on {target} ===", C.CYAN)
    if shutil.which("ssh"):
        res = run_ssh_capture(user, key, port, target, "LANG=C dpkg -l || rpm -qa || echo '(no package manager found)'", timeout=120)
        print(res[:20000])
        res2 = run_ssh_capture(user, key, port, target, "LANG=C which apt >/dev/null 2>&1 && apt policy || echo '(apt not present)'", timeout=30)
        print(res2)
    else:
        cprint("(ssh client not available locally)", C.YELLOW)

def remote_full_drives_ssh(user, key, port, target):
    cprint(f"\n=== Remote: Full Drives & Block Devices on {target} ===", C.CYAN)
    if shutil.which("ssh"):
        cmds = [
            "LANG=C lsblk -a -o NAME,FSTYPE,SIZE,MOUNTPOINT,LABEL,UUID,ROTA,MODEL || echo '(lsblk not present)'",
            "LANG=C blkid || echo '(blkid not present)'",
            "LANG=C fdisk -l || echo '(fdisk not present or requires privileges)'",
            "LANG=C which smartctl >/dev/null 2>&1 && (for d in $(lsblk -ndo NAME 2>/dev/null); do sudo smartctl -a /dev/$d || true; done) || echo '(smartctl not present)'"
        ]
        for cmd in cmds:
            out = run_ssh_capture(user, key, port, target, cmd, timeout=180)
            print(out[:20000])
    else:
        cprint("(ssh client not available locally)", C.YELLOW)

# ----------------------------
# Mounts, autoruns, logs
# ----------------------------
def mounts():
    time.sleep(0.05)
    cprint("\n=== Mounts & Disk Usage ===", C.CYAN)
    print(run(["mount"]))
    print(run(["df", "-h"]))

def autoruns():
    time.sleep(0.05)
    cprint("\n=== Autoruns / Cron / Services ===", C.CYAN)
    print(run(["systemctl", "list-unit-files", "--type=service"]))
    for f in ["/etc/crontab", "/etc/cron.d"]:
        p = Path(f)
        if p.exists():
            cprint(f"\n[{f}]", C.BOLD)
            print(safe_read(p, 3000))

def logs():
    time.sleep(0.05)
    cprint("\n=== Log Excerpts ===", C.CYAN)
    for f in ["/var/log/auth.log", "/var/log/syslog", "/var/log/messages"]:
        p = Path(f)
        if p.exists():
            cprint(f"\n[{f}]", C.BOLD)
            print(safe_read(p, 4000))
    print(run(["last", "-n", "5"]))

# ----------------------------
# Help & CLI parsing
# ----------------------------
def show_help(progname):
    banner()
    print(f"Usage:\n  {progname} [options]\n")
    print("Modes (mutually exclusive):")
    print("  --packages         Run only the packages scan (local)")
    print("  --drives           Run only the drives/partitions scan (local)")
    print("  --networks         Run only the network scan (local)")
    print("  --processes        Run detailed local process analysis")
    print("\nOptions:")
    print("  --target <IP|HOST>       Optional target IP or hostname to run remote network diagnostics against")
    print("  --remote-packages        Run full package enumeration on the target via SSH")
    print("  --remote-drives          Run full drive/partition inspection on the target via SSH")
    print("  --remote-processes       Run detailed process analysis on the target via SSH")
    print("  --ssh-user USER          SSH username (defaults to current user)")
    print("  --ssh-port PORT          SSH port (default 22)")
    print("  --ssh-key PATH           SSH identity file (optional)")
    print("  --no-remote              Skip remote checks even if --target provided")
    print("  --quick                  Skip heavy local steps (autoruns, packages, logs)")
    print("  --help, -h               Show help and exit")
    print("  --version                Show version info\n")
    print("Examples:")
    print("  sudo ./trace.py")
    print("  ./trace.py --quick")
    print("  ./trace.py --networks --target 8.8.8.8")
    print("  ./trace.py --remote-packages --target 10.0.0.5 --ssh-user=operator --ssh-key=/home/operator/.ssh/id_rsa")
    print("  ./trace.py --remote-drives --target 10.0.0.5 --ssh-user=root --ssh-port=2222")
    print("  ./trace.py --processes")
    print("  ./trace.py --remote-processes --target 10.0.0.5 --ssh-user=operator\n")
    print("Notes:")
    print("  - Remote package/drive/process inspection requires SSH access (key or agent). The script uses `ssh -o BatchMode=yes` and will fail fast if auth can't be performed.")
    print("  - Some remote commands may require elevated privileges on the remote host (sudo). The script attempts non-sudo reads and reports permission issues gracefully.")
    print("  - Script is read-only for collection commands and intended for forensic triage.\n")

def parse_args():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--packages", action="store_true", help="Scan packages only (local full output)")
    p.add_argument("--drives", action="store_true", help="Scan drives only (local full output)")
    p.add_argument("--networks", action="store_true", help="Scan networks only (local full output)")
    p.add_argument("--processes", action="store_true", help="Run detailed local process analysis")
    p.add_argument("--quick", action="store_true", help="Skip heavy local steps")
    p.add_argument("--help", "-h", action="store_true", help="Show help")
    p.add_argument("--version", action="store_true", help="Show version")
    p.add_argument("--target", type=str, help="Optional IP or hostname to run remote diagnostics against")
    p.add_argument("--remote-packages", action="store_true", help="Run full packages enumeration on the remote target via SSH")
    p.add_argument("--remote-drives", action="store_true", help="Run full drives inspection on the remote target via SSH")
    p.add_argument("--remote-processes", action="store_true", help="Run detailed processes inspection on the remote target via SSH")
    p.add_argument("--ssh-user", type=str, default=getpass.getuser(), help="SSH username for remote checks")
    p.add_argument("--ssh-port", type=int, default=22, help="SSH port for remote checks")
    p.add_argument("--ssh-key", type=str, help="SSH identity file (optional)")
    p.add_argument("--no-remote", action="store_true", help="Skip remote checks even if --target provided")
    args = p.parse_args()
    selected = sum([bool(args.packages), bool(args.drives), bool(args.networks), bool(args.processes)])
    if selected > 1:
        cprint("Error: --packages, --drives, --networks and --processes are mutually exclusive.", C.RED)
        safe_exit(2)
    return args

# ----------------------------
# Main
# ----------------------------
def main():
    args = parse_args()
    if args.help:
        show_help(sys.argv[0]); return
    if args.version:
        print("Trace v1.4r — Progress Edition"); return

    # banner & start
    banner()
    cprint(f"Started: {datetime.utcnow().isoformat()} UTC\n", C.YELLOW)

    target = args.target
    if target:
        cprint(f"Target specified: {target}\n", C.YELLOW)
        if args.no_remote:
            cprint("Remote checks are explicitly disabled (--no-remote).", C.YELLOW)

    ssh_user = args.ssh_user
    ssh_port = args.ssh_port
    ssh_key = args.ssh_key

    # build steps list
    steps = []
    # Mutual exclusive local-only modes handled earlier; if one selected, do only that local step
    if args.packages:
        steps = [("Full Packages (local)", lambda: full_packages())]
    elif args.drives:
        steps = [("Full Drives (local)", lambda: full_drives())]
    elif args.networks:
        steps = [("Full Networks (local)", lambda: full_networks(target=target if not args.no_remote else None))]
    elif args.processes:
        steps = [("Detailed Processes (local)", lambda: local_detailed_processes())]
    else:
        # Default full trace
        quick = args.quick
        steps = [
            ("System info", basic_info),
            ("Processes (sample)", processes_sample),
            ("Network", lambda: network(target=target if not args.no_remote else None)),
            ("Mounts", mounts),
        ]
        if not quick:
            steps += [
                ("Autoruns", autoruns),
                ("Packages (sample)", lambda: packages(sample=True)),
                ("Logs", logs)
            ]

    # Append remote explicit steps if requested and target present
    if target and not args.no_remote:
        if args.remote_packages:
            steps.append(("Remote: Full Packages (ssh)", lambda: remote_full_packages_ssh(ssh_user, ssh_key, ssh_port, target)))
        if args.remote_drives:
            steps.append(("Remote: Full Drives (ssh)", lambda: remote_full_drives_ssh(ssh_user, ssh_key, ssh_port, target)))
        if args.remote_processes:
            steps.append(("Remote: Detailed Processes (ssh)", lambda: remote_detailed_processes_ssh(ssh_user, ssh_key, ssh_port, target)))

    total = len(steps)
    start = time.time()

    for i, (name, fn) in enumerate(steps, 1):
        progress(i, total, f"Collecting {name}")
        try:
            fn()
            progress(i, total, f"Collecting {name}", "ok")
        except Exception as e:
            progress(i, total, f"Collecting {name}", "warn")
            cprint(f"\n[!] Error during {name}: {e}", C.YELLOW)

    elapsed = time.time() - start

    # summary area — only for default full run (not when explicit local-only modes provided)
    if not (args.packages or args.drives or args.networks or args.processes):
        cprint("\n──────────────────────────────────────────────", C.CYAN)
        cprint("Summary:", C.BOLD)
        print(f"Hostname: {socket.gethostname()}")
        users = [u.pw_name for u in pwd.getpwall() if (hasattr(u, 'pw_uid') and (u.pw_uid >= 1000 or u.pw_uid == 0))]
        print(f"Users: {', '.join(users)}")
        print(f"Elapsed Time: {elapsed:.2f}s")
        cprint("──────────────────────────────────────────────", C.CYAN)
        cprint("\n✅ Trace completed successfully.\n", C.GREEN)
    else:
        cprint("\n──────────────────────────────────────────────", C.CYAN)
        cprint(f"Completed requested scan(s) in {elapsed:.2f}s", C.BOLD)
        cprint("──────────────────────────────────────────────\n", C.CYAN)

if __name__ == "__main__":
    # allow ctrl-c cleanly
    try:
        main()
    except KeyboardInterrupt:
        cprint("\nInterrupted by user.", C.YELLOW)
        safe_exit(130)
