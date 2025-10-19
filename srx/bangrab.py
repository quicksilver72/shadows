#!/usr/bin/env python3
"""
bangrab - Lightweight Banner & Protocol Grabber
Purpose:
  Concurrently connect to a list of host:port targets, read initial bytes,
  and display banners / protocol hints directly to CLI output.

Usage:
  bangrab --targets hostlist.txt [--timeout 3] [--workers 200]
  bangrab --target 192.168.1.10:22
  bangrab --cidr 10.0.0.0/24 --ports 22,80,443

Output:
  host:port | protocol_guess | first banner line (truncated)

Notes:
  - One-shot, read-only TCP connects
  - No JSON/log files
  - Fully stdlib Python3
"""
import argparse
import concurrent.futures
import ipaddress
import socket
import sys
from typing import List, Tuple


def parse_target_line(line: str) -> Tuple[str, int]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if ":" in line:
        h, p = line.split(":", 1)
        return h.strip(), int(p)
    else:
        return line, 80


def expand_cidr(cidr: str, ports: List[int]) -> List[Tuple[str, int]]:
    targets = []
    for ip in ipaddress.ip_network(cidr, strict=False).hosts():
        for p in ports:
            targets.append((str(ip), p))
    return targets


def grab_banner(host: str, port: int, timeout: float) -> Tuple[str, int, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(512)
            except socket.timeout:
                data = b""
            banner = data.decode("utf-8", errors="replace").strip().replace("\n", " ")[:200]
            proto = guess_protocol(port, banner)
            return (host, port, f"{proto:<8} {banner}")
    except Exception:
        return (host, port, "closed/unreachable")


def guess_protocol(port: int, banner: str) -> str:
    low = banner.lower()
    if "ssh" in low or port == 22:
        return "ssh"
    if "smtp" in low or port == 25:
        return "smtp"
    if "http" in low or port in (80, 8080):
        return "http"
    if "ssl" in low or "tls" in low or port == 443:
        return "https"
    if "ftp" in low or port == 21:
        return "ftp"
    if "imap" in low or "pop" in low:
        return "mail"
    return "tcp"


def main():
    parser = argparse.ArgumentParser(
        prog="bangrab",
        description="High-speed banner & protocol grabber",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", help="Single host[:port]")
    parser.add_argument("--targets", help="File containing host[:port] lines")
    parser.add_argument("--cidr", help="CIDR to expand, e.g., 10.0.0.0/24")
    parser.add_argument("--ports", help="Comma-separated ports for CIDR mode", default="80,443,22")
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout seconds")
    parser.add_argument("--workers", type=int, default=200, help="Concurrent worker count")
    args = parser.parse_args()

    targets: List[Tuple[str, int]] = []

    if args.target:
        if ":" in args.target:
            h, p = args.target.split(":", 1)
            targets.append((h, int(p)))
        else:
            targets.append((args.target, 80))

    elif args.targets:
        try:
            with open(args.targets, "r", encoding="utf-8") as f:
                for line in f:
                    parsed = parse_target_line(line)
                    if parsed:
                        targets.append(parsed)
        except Exception as e:
            print(f"[!] Failed to read target file: {e}")
            sys.exit(1)

    elif args.cidr:
        ports = [int(p) for p in args.ports.split(",") if p.strip()]
        targets = expand_cidr(args.cidr, ports)

    else:
        parser.print_help()
        sys.exit(0)

    print(f"[*] Targets: {len(targets)} | Timeout: {args.timeout}s | Workers: {args.workers}")
    print("-" * 80)
    print(f"{'HOST':<18} {'PORT':<6} BANNER")
    print("-" * 80)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_target = {executor.submit(grab_banner, h, p, args.timeout): (h, p) for h, p in targets}
        for future in concurrent.futures.as_completed(future_to_target):
            h, p = future_to_target[future]
            try:
                host, port, result = future.result()
                print(f"{host:<18} {port:<6} {result}")
            except Exception:
                print(f"{h:<18} {p:<6} error retrieving banner")

    print("-" * 80)
    print("[*] Scan complete.")


if __name__ == "__main__":
    main()
