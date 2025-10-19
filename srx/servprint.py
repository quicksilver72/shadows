#!/usr/bin/env python3
"""
servprint - Service Behavior Fingerprinter (single-file)
Purpose:
  Probabilistic, non-destructive behavioral fingerprinting for network services.
  Sends a compact set of lightweight protocol probes and records response vectors
  (headers, status, body snippets, timing). Produces a concise, well-formatted
  CLI report suitable for rapid triage.

Usage:
  servprint --target host[:port] --protocol <http|https|smtp|ssh|generic> [--probes default|all]
             [--timeout secs]

Examples:
  servprint --target example.com --protocol https
  servprint --target 10.0.0.5:8025 --protocol smtp --timeout 6

Notes:
  - Probes are conservative and avoid state-changing operations.
  - Extend FINGERPRINT_DB within this file to add more signatures.
"""
from __future__ import annotations

import argparse
import re
import socket
import ssl
import sys
import time
from typing import Dict, List, Optional, Tuple

# -------------------------
# Compact fingerprint DB
# -------------------------
FINGERPRINT_DB = [
    {
        "name": "nginx",
        "tags": ["http", "proxy", "webserver"],
        "heuristics": [
            ("headers", r"Server:.*nginx", 3),
            ("body_snippet", r"nginx/[\d\.]+", 2),
            ("status_line", r"Server: nginx", 1),
        ],
    },
    {
        "name": "apache_httpd",
        "tags": ["http", "webserver"],
        "heuristics": [
            ("headers", r"Server:.*Apache", 3),
            ("body_snippet", r"Apache/[\d\.]+", 2),
            ("status_line", r"Apache", 1),
        ],
    },
    {
        "name": "iis",
        "tags": ["http", "microsoft"],
        "heuristics": [
            ("headers", r"Server:.*Microsoft-IIS", 3),
            ("body_snippet", r"Microsoft-IIS", 2),
        ],
    },
    {
        "name": "openssh",
        "tags": ["ssh", "server"],
        "heuristics": [
            ("banner", r"^SSH-(\d+\.\d+)-OpenSSH", 4),
        ],
    },
    {
        "name": "postfix",
        "tags": ["smtp", "mail"],
        "heuristics": [
            ("banner", r"^220 .*Postfix", 3),
            ("body_snippet", r"Postfix", 1),
        ],
    },
    {
        "name": "exim",
        "tags": ["smtp", "mail"],
        "heuristics": [
            ("banner", r"^220 .*Exim", 3),
        ],
    },
    # Add more fingerprint entries as required.
]

# -------------------------
# Helpers
# -------------------------
def now_ms() -> float:
    return time.time() * 1000.0

def read_n_bytes(sock: socket.socket, n: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    remaining = n
    try:
        while remaining > 0:
            data = sock.recv(min(4096, remaining))
            if not data:
                break
            chunks.append(data)
            remaining -= len(data)
    except socket.timeout:
        pass
    except Exception:
        pass
    return b"".join(chunks)

def safe_decode(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:
        return repr(b)

def regex_search_any(source: str, pattern: str, flags=0) -> bool:
    try:
        return re.search(pattern, source, flags) is not None
    except re.error:
        return False

def split_lines(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    return "\n".join(lines[:max_lines])

def horizontal_rule(char: str = "-", width: int = 80) -> str:
    return char * width

def print_section(title: str) -> None:
    print()
    print(horizontal_rule("="))
    print(f" {title}")
    print(horizontal_rule("-"))

# -------------------------
# Probes
# -------------------------
def probe_http(host: str, port: int, use_tls: bool, timeout: float) -> Dict:
    evidence = {
        "protocol": "https" if use_tls else "http",
        "host": host,
        "port": port,
        "probes": [],
        "headers": "",
        "status_line": "",
        "body_snippet": "",
        "cert_subject": None,
    }

    try:
        addr_info = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception:
        addr_info = None

    context = None
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    def open_sock(timeout_local: float) -> Optional[socket.socket]:
        try:
            if addr_info:
                af, socktype, proto, _, sa = addr_info[0]
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(timeout_local)
                s.connect(sa)
                return s
            else:
                s = socket.create_connection((host, port), timeout=timeout_local)
                return s
        except Exception:
            return None

    # HEAD probe
    head_probe = {"name": "HEAD", "status": None, "duration_ms": None, "raw_response": None}
    t0 = now_ms()
    s = open_sock(timeout)
    if s:
        try:
            if use_tls and context:
                s = context.wrap_socket(s, server_hostname=host)
                try:
                    cert = s.getpeercert()
                    if cert and "subject" in cert:
                        subj = []
                        for tup in cert.get("subject", ()):
                            subj.append("=".join(tup[0]))
                        evidence["cert_subject"] = ", ".join(subj)
                except Exception:
                    pass
            req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: servfprint/1.0\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode("ascii", errors="ignore"))
            raw = read_n_bytes(s, 8192, timeout)
            dur = now_ms() - t0
            txt = safe_decode(raw)
            lines = txt.splitlines()
            if lines:
                evidence["status_line"] = lines[0]
            evidence["headers"] = "\n".join(lines[1:40])
            evidence["body_snippet"] = split_lines("\n".join(lines[40:45]), 5)[:1024]
            head_probe["status"] = evidence["status_line"]
            head_probe["duration_ms"] = int(dur)
            head_probe["raw_response"] = txt[:4096]
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass
    else:
        head_probe["status"] = "connect_failed"
        head_probe["duration_ms"] = 0
    evidence["probes"].append(head_probe)

    # Invalid method probe
    invalid_probe = {"name": "INVALID_METHOD", "status": None, "duration_ms": None, "raw_response": None}
    t0 = now_ms()
    s = open_sock(timeout)
    if s:
        try:
            if use_tls and context:
                s = context.wrap_socket(s, server_hostname=host)
            req = f"BREW / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: servfprint/1.0\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode("ascii", errors="ignore"))
            raw = read_n_bytes(s, 8192, timeout)
            dur = now_ms() - t0
            txt = safe_decode(raw)
            invalid_probe["status"] = txt.splitlines()[0] if txt else ""
            invalid_probe["duration_ms"] = int(dur)
            invalid_probe["raw_response"] = txt[:4096]
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass
    else:
        invalid_probe["status"] = "connect_failed"
        invalid_probe["duration_ms"] = 0
    evidence["probes"].append(invalid_probe)

    # Long path probe
    longpath_probe = {"name": "LONG_PATH", "status": None, "duration_ms": None, "raw_response": None}
    t0 = now_ms()
    s = open_sock(timeout)
    if s:
        try:
            if use_tls and context:
                s = context.wrap_socket(s, server_hostname=host)
            path = "/" + ("A" * 1024)
            req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: servfprint/1.0\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode("ascii", errors="ignore"))
            raw = read_n_bytes(s, 8192, timeout)
            dur = now_ms() - t0
            txt = safe_decode(raw)
            longpath_probe["status"] = txt.splitlines()[0] if txt else ""
            longpath_probe["duration_ms"] = int(dur)
            longpath_probe["raw_response"] = txt[:4096]
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass
    else:
        longpath_probe["status"] = "connect_failed"
        longpath_probe["duration_ms"] = 0
    evidence["probes"].append(longpath_probe)

    return evidence

def probe_ssh(host: str, port: int, timeout: float) -> Dict:
    evidence = {"protocol": "ssh", "host": host, "port": port, "banner": "", "probes": []}
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        data = read_n_bytes(s, 256, timeout)
        banner = safe_decode(data).strip()
        evidence["banner"] = banner
        evidence["probes"].append({"name": "BANNER", "raw": banner})
        try:
            s.close()
        except Exception:
            pass
    except Exception:
        evidence["banner"] = ""
    return evidence

def probe_smtp(host: str, port: int, timeout: float) -> Dict:
    evidence = {"protocol": "smtp", "host": host, "port": port, "banner": "", "ehlo": "", "probes": []}
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        raw = read_n_bytes(s, 1024, timeout)
        banner = safe_decode(raw).strip()
        try:
            s.sendall(b"EHLO servfprint.example\r\n")
            resp = read_n_bytes(s, 2048, timeout)
            ehlo = safe_decode(resp).strip()
        except Exception:
            ehlo = ""
        evidence["banner"] = banner
        evidence["ehlo"] = ehlo
        evidence["probes"].append({"name": "BANNER", "raw": banner})
        evidence["probes"].append({"name": "EHLO", "raw": ehlo})
        try:
            s.close()
        except Exception:
            pass
    except Exception:
        pass
    return evidence

def probe_generic_tcp(host: str, port: int, timeout: float) -> Dict:
    evidence = {"protocol": "tcp", "host": host, "port": port, "banner": "", "probes": []}
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        data = read_n_bytes(s, 4096, timeout)
        banner = safe_decode(data).strip()
        evidence["banner"] = banner
        evidence["probes"].append({"name": "BANNER", "raw": banner})
        try:
            s.close()
        except Exception:
            pass
    except Exception:
        pass
    return evidence

# -------------------------
# Fingerprint scoring
# -------------------------
def score_fingerprints(evidence: Dict) -> List[Dict]:
    combined_text = ""
    fields = [
        evidence.get("status_line", ""),
        evidence.get("headers", ""),
        evidence.get("body_snippet", ""),
        evidence.get("banner", ""),
        evidence.get("cert_subject", "") or "",
        evidence.get("ehlo", "") or "",
    ]
    combined_text = "\n".join([f for f in fields if f])
    results = []
    for entry in FINGERPRINT_DB:
        score = 0
        matches = []
        for (field, pattern, weight) in entry.get("heuristics", []):
            hay = ""
            if field == "headers":
                hay = evidence.get("headers", "")
            elif field == "status_line":
                hay = evidence.get("status_line", "")
            elif field == "body_snippet":
                hay = evidence.get("body_snippet", "")
            elif field == "banner":
                hay = evidence.get("banner", "")
            elif field == "cert_subject":
                hay = evidence.get("cert_subject", "") or ""
            elif field == "ehlo":
                hay = evidence.get("ehlo", "") or ""
            else:
                hay = combined_text
            if regex_search_any(hay, pattern, flags=re.IGNORECASE):
                score += weight
                matches.append({"pattern": pattern, "weight": weight})
        results.append({"name": entry["name"], "tags": entry.get("tags", []), "score": score, "matches": matches})
    results.sort(key=lambda x: x["score"], reverse=True)
    return results

# -------------------------
# Output formatting
# -------------------------
def print_header(target: str, protocol: str) -> None:
    print(horizontal_rule("="))
    print(f" servprint - Service Behavior Fingerprinter")
    print(f" Target  : {target}")
    print(f" Protocol: {protocol}")
    print(f" Time    : {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC")
    print(horizontal_rule("-"))

def print_evidence(evidence: Dict) -> None:
    print_section("Collected Evidence")
    print(f"Protocol : {evidence.get('protocol')}")
    print(f"Host     : {evidence.get('host')}:{evidence.get('port')}")
    cert = evidence.get("cert_subject")
    if cert:
        print(f"Cert Subj: {cert}")
    # Print status line and headers if present
    status = evidence.get("status_line", "")
    if status:
        print()
        print("Status Line:")
        print(f"  {status}")
    headers = evidence.get("headers", "")
    if headers:
        print()
        print("Headers (first lines):")
        for ln in headers.splitlines()[:20]:
            print(f"  {ln}")
    body = evidence.get("body_snippet", "")
    if body:
        print()
        print("Body snippet:")
        for ln in body.splitlines():
            print(f"  {ln}")
    # Banners and probe summaries
    probes = evidence.get("probes", [])
    if probes:
        print()
        print("Probe Summary:")
        for p in probes:
            name = p.get("name")
            status = p.get("status")
            dur = p.get("duration_ms")
            print(f"  [{name}] status: {status}  duration_ms: {dur}")
    # Additional banners
    banner = evidence.get("banner", "")
    if banner:
        print()
        print("Banner:")
        for ln in banner.splitlines()[:10]:
            print(f"  {ln}")
    ehlo = evidence.get("ehlo", "")
    if ehlo:
        print()
        print("EHLO response:")
        for ln in ehlo.splitlines()[:10]:
            print(f"  {ln}")

def print_matches(matches: List[Dict], top_n: int = 6) -> None:
    print_section("Fingerprint Matches")
    if not matches:
        print(" No fingerprint candidates.")
        return
    # Print top matches
    for i, m in enumerate(matches[:top_n], 1):
        score = m.get("score", 0)
        tags = ",".join(m.get("tags", []))
        print(f" {i}. {m['name']}  (score: {score})  tags: [{tags}]")
        if m.get("matches"):
            for mm in m["matches"]:
                pat = mm.get("pattern")
                wt = mm.get("weight")
                print(f"     - matched pattern: {pat} (weight {wt})")
    # If best is zero score, indicate no confident match
    best = matches[0] if matches else None
    if best and best.get("score", 0) == 0:
        print()
        print(" No confident fingerprint match found (all scores 0).")

# -------------------------
# CLI / Orchestration
# -------------------------
def parse_target(arg: str) -> Tuple[str, Optional[int]]:
    if ":" in arg:
        host, port = arg.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return host, None
    return arg, None

def main() -> None:
    p = argparse.ArgumentParser(
        prog="servprint",
        description="Service Behavior Fingerprinter - concise CLI report output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target", required=True, help="Target host or host:port")
    p.add_argument(
        "--protocol",
        choices=["http", "https", "ssh", "smtp", "generic"],
        default="http",
        help="Protocol to probe (default: http)",
    )
    p.add_argument("--probes", choices=["default", "all"], default="default", help="Probe set to run")
    p.add_argument("--timeout", type=float, default=4.0, help="Per-probe timeout seconds")
    args = p.parse_args()

    host, pport = parse_target(args.target)
    port_map = {"http": 80, "https": 443, "ssh": 22, "smtp": 25}
    port = pport or port_map.get(args.protocol, 0)
    if port == 0:
        print("Unable to determine port; specify host:port")
        sys.exit(2)

    target_label = f"{host}:{port}"
    print_header(target_label, args.protocol)

    if args.protocol in ("http", "https"):
        use_tls = args.protocol == "https"
        evidence = probe_http(host, port, use_tls, args.timeout)
        matches = score_fingerprints(evidence)
    elif args.protocol == "ssh":
        evidence = probe_ssh(host, port, args.timeout)
        matches = score_fingerprints(evidence)
    elif args.protocol == "smtp":
        evidence = probe_smtp(host, port, args.timeout)
        matches = score_fingerprints(evidence)
    else:
        evidence = probe_generic_tcp(host, port, args.timeout)
        matches = score_fingerprints(evidence)

    print_evidence(evidence)
    print_matches(matches)

    # Summary line
    print()
    print(horizontal_rule("="))
    best = matches[0] if matches else None
    if best and best.get("score", 0) > 0:
        print(f" Primary guess: {best['name']} (score {best['score']})")
    else:
        print(" Primary guess: <none - no confident match>")
    print(horizontal_rule("="))

if __name__ == "__main__":
    main()
