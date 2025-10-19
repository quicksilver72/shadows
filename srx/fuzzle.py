#!/usr/bin/env python3
"""
Fuzzle — One-shot Mutational Fuzzer
Author: quicksilver
Version: 1.0
"""

from __future__ import annotations
import argparse
import os
import sys
import random
import socket
import time
import traceback
from datetime import datetime
from typing import Tuple

# --------------------------
# Terminal color utilities
# --------------------------
class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def color(text: str, code: str) -> str:
    return f"{code}{text}{C.RESET}"

def info(msg: str):
    print(color("[*] ", C.CYAN) + msg)

def warn(msg: str):
    print(color("[!] ", C.YELLOW) + msg)

def fail(msg: str):
    print(color("[X] ", C.RED) + msg)

def ok(msg: str):
    print(color("[+] ", C.GREEN) + msg)

# --------------------------
# Application directories
# --------------------------
HOME = os.path.expanduser("~")
FUZZ_DIR = os.path.join(HOME, ".fuzzle")
LOG_DIR = os.path.join(FUZZ_DIR, "logs")
CRASH_DIR = os.path.join(FUZZ_DIR, "crashes")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(CRASH_DIR, exist_ok=True)

def write_log(line: str):
    fname = os.path.join(LOG_DIR, f"fuzzle-{datetime.utcnow().strftime('%Y%m%d')}.log")
    try:
        with open(fname, "a") as f:
            f.write(f"{datetime.utcnow().isoformat()} {line}\n")
    except Exception:
        pass

# --------------------------
# Utilities
# --------------------------
def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def progress_bar(current: int, total: int, width: int = 40) -> str:
    if total <= 0:
        return ""
    ratio = float(current) / float(total)
    filled = int(ratio * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {current}/{total}"

# --------------------------
# Mutation strategies
# --------------------------
def mut_bitflip(data: bytearray, intensity: int = 1) -> bytearray:
    out = bytearray(data)
    for _ in range(intensity):
        if not out:
            break
        idx = random.randrange(len(out))
        bit = 1 << random.randrange(8)
        out[idx] ^= bit
    return out

def mut_insert_random(data: bytearray, max_insert: int = 16) -> bytearray:
    out = bytearray(data)
    n = random.randint(1, max_insert)
    pos = random.randrange(len(out) + 1) if out else 0
    out[pos:pos] = os.urandom(n)
    return out

def mut_delete_chunk(data: bytearray, max_del: int = 16) -> bytearray:
    out = bytearray(data)
    if not out:
        return out
    n = random.randint(1, min(max_del, len(out)))
    pos = random.randrange(len(out) - n + 1)
    del out[pos:pos+n]
    return out

def mut_duplicate_block(data: bytearray, max_block: int = 32) -> bytearray:
    out = bytearray(data)
    if not out:
        return out
    block = os.urandom(random.randint(1, min(max_block, len(out))))
    pos = random.randrange(len(out) + 1)
    out[pos:pos] = block
    return out

def mut_random_bytes(data: bytearray, nbytes: int = 8) -> bytearray:
    out = bytearray(data)
    if not out:
        return out
    pos = random.randrange(len(out))
    n = min(nbytes, len(out) - pos)
    out[pos:pos+n] = os.urandom(n)
    return out

MUTATORS = [
    ("bitflip", mut_bitflip),
    ("insert", mut_insert_random),
    ("delete", mut_delete_chunk),
    ("dup", mut_duplicate_block),
    ("rand", mut_random_bytes),
]

def choose_mutator() -> Tuple[str, callable]:
    name, fn = random.choice(MUTATORS)
    return name, fn

# --------------------------
# Fuzzing engines
# --------------------------
def fuzz_file_mode(sample: bytes, mutations: int, outdir: str, report: dict, max_mut_size: int, simulate_write: bool):
    info(f"File-mode: sample {len(sample)} bytes, mutations {mutations}, outdir {outdir}")
    os.makedirs(outdir, exist_ok=True)
    for i in range(1, mutations + 1):
        name, fn = choose_mutator()
        intensity = random.randint(1, 8)
        try:
            mutated = fn(bytearray(sample), intensity) if name == "bitflip" else fn(bytearray(sample))
            fname = os.path.join(outdir, f"mut_{i:06d}_{name}.bin")
            if not simulate_write:
                with open(fname, "wb") as f:
                    f.write(mutated)
            report["generated"] += 1
            report["mut_details"].append((i, name, len(mutated)))
            if len(mutated) == 0 or len(mutated) > max_mut_size:
                report["crashes"].append((fname, "size_anomaly"))
                if not simulate_write:
                    save_crash_payload(fname, mutated, "size_anomaly")
                write_log(f"CRASH(size) {fname}")
                print(color(f"\n[CRASH] file {fname} size anomaly ({len(mutated)} bytes)", C.RED))
        except Exception as e:
            report["errors"].append((i, str(e)))
            write_log(f"ERROR mutating #{i}: {e}")
        sys.stdout.write("\r" + progress_bar(i, mutations) + f"  last:{name} ")
        sys.stdout.flush()
    print()
    return report

def fuzz_tcp_mode(sample: bytes, mutations: int, host: str, port: int, send_enabled: bool,
                  rate: float, timeout: float, report: dict, max_resp_len: int, simulate_write: bool):
    info(f"TCP-mode: target {host}:{port}, mutations {mutations}, send_enabled={send_enabled}, rate={rate}pps")
    for i in range(1, mutations + 1):
        name, fn = choose_mutator()
        intensity = random.randint(1, 8)
        try:
            mutated = fn(bytearray(sample), intensity) if name == "bitflip" else fn(bytearray(sample))
        except Exception as e:
            report["errors"].append((i, str(e)))
            write_log(f"ERROR mutating #{i}: {e}")
            mutated = bytearray(sample)

        report["generated"] += 1
        report["mut_details"].append((i, name, len(mutated)))

        if not send_enabled:
            sys.stdout.write("\r" + progress_bar(i, mutations) + f"  last:{name} (simulated)")
            sys.stdout.flush()
            time.sleep(max(0, 1.0 / rate) if rate > 0 else 0)
            continue

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(mutated)
            try:
                resp = sock.recv(max_resp_len)
                if len(resp) == 0:
                    report["crashes"].append((i, "conn_closed"))
                    if not simulate_write:
                        save_crash_payload_tcp(i, mutated, "conn_closed")
                    write_log(f"CRASH(conn_closed) iter={i}")
                    print(color(f"\n[CRASH] connection closed by remote on iter {i}", C.RED))
            except socket.timeout:
                report["crashes"].append((i, "timeout"))
                if not simulate_write:
                    save_crash_payload_tcp(i, mutated, "timeout")
                write_log(f"CRASH(timeout) iter={i}")
                print(color(f"\n[CRASH] timeout waiting for response on iter {i}", C.RED))
            finally:
                sock.close()
        except Exception as e:
            report["crashes"].append((i, f"connect_error:{e}"))
            if not simulate_write:
                save_crash_payload_tcp(i, mutated, f"connect_error:{e}")
            write_log(f"CRASH(connect_error) iter={i} err={e}")
            print(color(f"\n[CRASH] connection error on iter {i}: {e}", C.RED))

        sys.stdout.write("\r" + progress_bar(i, mutations) + f"  last:{name} ")
        sys.stdout.flush()
        if rate > 0:
            time.sleep(max(0, 1.0 / rate))
    print()
    return report

# --------------------------
# Crash persistence
# --------------------------
def save_crash_payload(path_or_idx, payload: bytes, reason: str):
    try:
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        safe_base = os.path.basename(str(path_or_idx))[:120]
        fname = f"crash_{ts}_{reason}_{safe_base}"
        dest = os.path.join(CRASH_DIR, fname)
        with open(dest, "wb") as f:
            f.write(payload)
        meta = dest + ".meta.txt"
        with open(meta, "w") as m:
            m.write(f"time: {now_iso()}\nreason: {reason}\nsource: {path_or_idx}\nsize: {len(payload)}\n")
        return dest
    except Exception:
        return None

def save_crash_payload_tcp(iter_idx: int, payload: bytes, reason: str):
    try:
        return save_crash_payload(f"iter{iter_idx}", payload, reason)
    except Exception:
        return None

# --------------------------
# Reporting
# --------------------------
def summarise_report(report: dict, elapsed: float):
    print()
    info("Fuzzing summary:")
    print(f"  Generated payloads: {report['generated']}")
    print(f"  Crashes detected  : {len(report['crashes'])}")
    print(f"  Suspicious events : {len(report['suspicious'])}")
    print(f"  Errors            : {len(report['errors'])}")
    if report['crashes']:
        print(color("  Crash samples saved in: " + CRASH_DIR, C.RED))
    print(f"  Time elapsed      : {elapsed:.2f}s")
    score = 100 - min(100, len(report['crashes']) * 6 + len(report['suspicious']) * 3 + len(report['errors']))
    score_color = C.GREEN if score >= 70 else C.YELLOW if score >= 40 else C.RED
    print(f"\nSecurity score: {color(str(score) + '/100', score_color)}")
    write_log(f"Fuzz summary generated={report['generated']} crashes={len(report['crashes'])} time={elapsed:.2f}s score={score}")

# --------------------------
# Help & CLI setup
# --------------------------
def show_help():
    print(color("\n╔══════════════════════════════════════════════════════════╗", C.CYAN))
    print(color("║                        F U Z Z L E                       ║", C.CYAN))
    print(color("╚══════════════════════════════════════════════════════════╝\n", C.CYAN))
    print("""Usage:
  fuzzle --mode <file|tcp> --sample <path> [options]

Examples:
  fuzzle --mode file --sample sample.bin --mutations 100 --outdir ./out
  fuzzle --mode tcp --sample sample.bin --host 127.0.0.1 --port 9000 --mutations 200
  sudo fuzzle --mode tcp --sample sample.bin --host 10.0.0.5 --port 9999 --mutations 500 --send --rate 200

Options:
  --mode <file|tcp>       Fuzzing mode (required)
  --sample <path>         Path to binary or text sample (required)
  --mutations N           Number of mutated payloads to generate (default 200)
  --outdir PATH           Output directory for results (default ./fuzzle_out)
  --host HOST             Target host (for TCP mode)
  --port PORT             Target port (for TCP mode)
  --send                  Explicit opt-in to send traffic (safe default = off)
  --simulate              Prevent writing crash files (dry-run mode)
  --rate PPS              Packets per second (default unlimited)
  --timeout SECONDS       Socket timeout (default 2.0)
  --max-resp BYTES        Maximum bytes to read (default 4096)
  --max-mut-size BYTES    Max mutated payload size before flagged (default 10MB)
  --version               Show version and exit
  --help, -h              Show this help and exit

Notes:
  - Safe by default: requires --send to actually transmit packets.
  - Simulation mode is perfect for safe local tests.
  - Crash files saved to ~/.fuzzle/crashes
  - Logs written to ~/.fuzzle/logs
""")

def build_parser():
    p = argparse.ArgumentParser(prog="fuzzle", add_help=False)
    p.add_argument("--mode", choices=["file", "tcp"], required=True)
    p.add_argument("--sample", required=True)
    p.add_argument("--mutations", type=int, default=200)
    p.add_argument("--outdir", default="./fuzzle_out")
    p.add_argument("--max-mut-size", type=int, default=10 * 1024 * 1024)
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--send", action="store_true")
    p.add_argument("--rate", type=float, default=0)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--max-resp", type=int, default=4096)
    p.add_argument("--simulate", action="store_true")
    p.add_argument("--help", "-h", action="store_true")
    p.add_argument("--version", action="store_true")
    return p

# --------------------------
# Main execution
# --------------------------
def main():
    parser = build_parser()

    # Early handle --help and --version
    if "--help" in sys.argv or "-h" in sys.argv:
        show_help()
        sys.exit(0)
    if "--version" in sys.argv:
        print("Fuzzle v1.0 — Mutational Fuzzer (Kali Edition)")
        sys.exit(0)

    args = parser.parse_args()

    mode = args.mode
    sample_path = args.sample

    if not os.path.exists(sample_path):
        fail(f"Sample not found: {sample_path}")
        sys.exit(2)
    if mode == "tcp" and (not args.host or not args.port):
        fail("TCP mode requires --host and --port")
        sys.exit(2)

    report = {"generated": 0, "crashes": [], "suspicious": [], "errors": [], "mut_details": []}

    try:
        with open(sample_path, "rb") as f:
            sample = f.read()
    except Exception as e:
        fail(f"Failed to load sample: {e}")
        sys.exit(1)

    write_log(f"START mode={mode} sample={sample_path} muts={args.mutations}")
    start_time = time.time()
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    run_outdir = os.path.join(outdir, f"run_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}")
    os.makedirs(run_outdir, exist_ok=True)

    send_enabled = args.send and (mode == "tcp")
    simulate_write = args.simulate

    if args.simulate:
        warn("Simulation mode ON: crash files will not be written, network sends suppressed.")
        send_enabled = False

    try:
        if mode == "file":
            report = fuzz_file_mode(sample, args.mutations, run_outdir, report, args.max_mut_size, simulate_write)
        else:
            report = fuzz_tcp_mode(sample, args.mutations, args.host, args.port, send_enabled,
                                   args.rate, args.timeout, report, args.max_resp, simulate_write)
    except KeyboardInterrupt:
        warn("Interrupted by user.")
    except Exception as e:
        fail(f"Fatal error during fuzzing: {e}")
        write_log("FATAL " + traceback.format_exc())

    elapsed = time.time() - start_time
    summarise_report(report, elapsed)

    summary_file = os.path.join(run_outdir, f"summary_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.txt")
    try:
        with open(summary_file, "w") as s:
            s.write(f"Fuzzle Summary — {now_iso()}\nMode: {mode}\nSample: {sample_path}\nElapsed: {elapsed:.2f}s\n")
            s.write(f"Generated: {report['generated']}\nCrashes: {len(report['crashes'])}\nErrors: {len(report['errors'])}\n")
        ok(f"Summary saved to {summary_file}")
    except Exception:
        warn("Failed to write summary file")

    info("Fuzzle finished")
    write_log(f"END mode={mode} generated={report['generated']} crashes={len(report['crashes'])}")

if __name__ == "__main__":
    main()
