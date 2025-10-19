#!/usr/bin/env python3
"""
PulseLine — Network Activity Visualizer (Terminal)

A real-time terminal-based network activity visualizer for operational use.
Designed for Kali and similar distributions where `scapy` is available.

Run as root (packet sniffing requires elevated permissions).

This script captures live packets on the specified interface and shows:
  - aggregated packet and byte rates (rolling window)
  - top talkers (by bytes)
  - protocol distribution (by bytes)
  - a compact time-series packet-rate graph
  - simple threshold alerts for high PPS / B/s

Controls (while running):
  q  - Quit
  p  - Pause / Resume capture
  c  - Clear counters
  i  - Show interface brief info

Author: quicksilver
"""

from __future__ import annotations
import argparse
import collections
import threading
import time
import signal
import socket
import sys
import curses
from typing import Deque, Dict, Tuple

# Attempt to import scapy; if missing, fail with instruction.
try:
    from scapy.all import sniff, conf, Ether, IP, IPv6, TCP, UDP, ICMP
except Exception as e:
    sys.stderr.write(
        "ERROR: scapy is required. On Kali: sudo apt update && sudo apt install python3-scapy\n"
        "Or install in venv: pip install scapy\n"
    )
    raise

# ---------- Configuration defaults ----------
ROLLING_SECONDS = 30
BUCKET_SECONDS = 1
TOP_TALKERS = 8
ALERT_PPS_THRESHOLD = 1000
ALERT_BPS_THRESHOLD = 10 * 1024 * 1024
REFRESH_INTERVAL = 0.5

# ---------- Data structures ----------
class StatsBucket:
    def __init__(self):
        self.pkt_count = 0
        self.byte_count = 0

class RollingSeries:
    def __init__(self, length: int):
        self.length = length
        self.deque: Deque[Tuple[int, int]] = collections.deque(maxlen=length)
        for _ in range(length):
            self.deque.append((0, 0))

    def append(self, pkts: int, byt: int):
        self.deque.append((pkts, byt))

    def totals(self) -> Tuple[int, int]:
        pkts = sum(p for p, b in self.deque)
        byt = sum(b for p, b in self.deque)
        return pkts, byt

    def to_list(self):
        return list(self.deque)

# ---------- Global State ----------
class GlobalState:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = True
        self.paused = False
        self.series = RollingSeries(ROLLING_SECONDS)
        self.current_bucket = StatsBucket()
        self.last_bucket_time = int(time.time())
        self.hosts: Dict[str, Dict[str, int]] = {}
        self.protocol_counts = collections.Counter()
        self.protocol_bytes = collections.Counter()
        self.last_alert = None
        self.iface = None

state = GlobalState()

# ---------- Packet Processing ----------
def process_packet(pkt):
    if state.paused:
        return
    t = int(time.time())
    with state.lock:
        if t != state.last_bucket_time:
            state.series.append(state.current_bucket.pkt_count, state.current_bucket.byte_count)
            state.current_bucket = StatsBucket()
            state.last_bucket_time = t
        try:
            raw_len = len(pkt)
        except Exception:
            raw_len = 0
        state.current_bucket.pkt_count += 1
        state.current_bucket.byte_count += raw_len

        proto = "OTHER"
        if IP in pkt:
            ip_layer = pkt[IP]
            src, dst = ip_layer.src, ip_layer.dst
            hsrc = state.hosts.setdefault(src, {"bytes_sent": 0, "bytes_recv": 0, "pkts": 0})
            hdst = state.hosts.setdefault(dst, {"bytes_sent": 0, "bytes_recv": 0, "pkts": 0})
            hsrc["bytes_sent"] += raw_len
            hsrc["pkts"] += 1
            hdst["bytes_recv"] += raw_len
            hdst["pkts"] += 1

            if TCP in pkt:
                proto = "TCP"
            elif UDP in pkt:
                proto = "UDP"
            elif ICMP in pkt:
                proto = "ICMP"
            else:
                proto = "IP"
        elif IPv6 in pkt:
            ip6 = pkt[IPv6]
            src, dst = ip6.src, ip6.dst
            hsrc = state.hosts.setdefault(src, {"bytes_sent": 0, "bytes_recv": 0, "pkts": 0})
            hdst = state.hosts.setdefault(dst, {"bytes_sent": 0, "bytes_recv": 0, "pkts": 0})
            hsrc["bytes_sent"] += raw_len
            hsrc["pkts"] += 1
            hdst["bytes_recv"] += raw_len
            hdst["pkts"] += 1
            if TCP in pkt:
                proto = "TCPv6"
            elif UDP in pkt:
                proto = "UDPv6"
            else:
                proto = "IPV6"
        else:
            proto = pkt.sprintf("%Pr")

        state.protocol_counts[proto] += 1
        state.protocol_bytes[proto] += raw_len

# ---------- Capture Thread ----------
def capture_thread(iface: str, bpf_filter: str | None):
    try:
        sniff(iface=iface, prn=process_packet, store=False, filter=bpf_filter)
    except PermissionError:
        sys.stderr.write("Permission denied: sniffing requires root. Run with sudo.\n")
        state.running = False
    except Exception as e:
        sys.stderr.write(f"Capture error: {e}\n")
        state.running = False

# ---------- Utility ----------
def nice_bytes(n: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"

def get_top_talkers(n=TOP_TALKERS):
    with state.lock:
        items = [(v.get("bytes_sent", 0) + v.get("bytes_recv", 0), ip, v)
                 for ip, v in state.hosts.items()]
        items.sort(reverse=True, key=lambda x: x[0])
        return items[:n]

def get_protocol_snapshot():
    with state.lock:
        items = list(state.protocol_bytes.items())
        items.sort(key=lambda x: x[1], reverse=True)
        return items[:12]

def reset_counters():
    with state.lock:
        state.series = RollingSeries(ROLLING_SECONDS)
        state.current_bucket = StatsBucket()
        state.last_bucket_time = int(time.time())
        state.hosts.clear()
        state.protocol_counts.clear()
        state.protocol_bytes.clear()
        state.last_alert = None

# ---------- UI ----------
def draw_ui(stdscr, iface: str):
    curses.use_default_colors()
    stdscr.nodelay(True)
    curses.curs_set(0)
    height, width = stdscr.getmaxyx()
    title = f"PulseLine — Live Network Visualizer — iface: {iface} — q:quit p:pause c:clear i:info"
    stdscr.clear()
    stdscr.addstr(0, 0, title[:width - 1], curses.A_BOLD)
    last_refresh = 0.0

    while state.running:
        try:
            ch = stdscr.getch()
            if ch != -1:
                if ch in (ord('q'), ord('Q')):
                    state.running = False
                    break
                elif ch in (ord('p'), ord('P')):
                    state.paused = not state.paused
                elif ch in (ord('c'), ord('C')):
                    reset_counters()
                elif ch in (ord('i'), ord('I')):
                    try:
                        mac = conf.iface.mac if hasattr(conf.iface, "mac") else "N/A"
                    except Exception:
                        mac = "N/A"
                    stdscr.addstr(1, 0, f"Interface: {iface}  MAC: {mac}     "[:width - 1])

            now = time.time()
            if now - last_refresh < REFRESH_INTERVAL:
                time.sleep(0.05)
                continue
            last_refresh = now

            stdscr.erase()
            stdscr.addstr(0, 0, title[:width - 1], curses.A_BOLD)

            with state.lock:
                cur_pkts = state.current_bucket.pkt_count
                cur_bytes = state.current_bucket.byte_count
                series_list = state.series.to_list()

            total_pkts_recent = sum(p for p, _ in series_list) + cur_pkts
            total_bytes_recent = sum(b for _, b in series_list) + cur_bytes
            pps = total_pkts_recent / max(1, ROLLING_SECONDS)
            bps = total_bytes_recent / max(1, ROLLING_SECONDS)
            header_line = f"PPS(avg {pps:.1f})  B/s(avg {nice_bytes(int(bps))})  Buckets:{ROLLING_SECONDS}s  Paused:{state.paused}"
            stdscr.addstr(1, 0, header_line[:width - 1])

            # Alert Line
            alert_msg = ""
            if pps > ALERT_PPS_THRESHOLD or bps > ALERT_BPS_THRESHOLD:
                alert_msg = f"ALERT: High traffic — PPS {pps:.1f}  B/s {nice_bytes(int(bps))}"
            if alert_msg:
                stdscr.addstr(2, 0, alert_msg[:width - 1], curses.A_REVERSE)
            else:
                stdscr.addstr(2, 0, " " * (width - 1))

            # Left: Protocols
            proto_snapshot = get_protocol_snapshot()
            left_col_width = max(30, int(width * 0.36))
            stdscr.addstr(4, 0, "Protocol Distribution (by bytes):", curses.A_UNDERLINE)
            total_proto_bytes = sum(b for _, b in proto_snapshot) or 1
            for i, (proto, byt) in enumerate(proto_snapshot):
                bar_y = 5 + i
                pct = (byt / total_proto_bytes) * 100
                bar_len = max(1, int((left_col_width - 24) * pct / 100))
                bar = ("█" * bar_len).ljust(left_col_width - 24)
                stdscr.addstr(bar_y, 0, f"{proto:<8} {nice_bytes(byt):>8} {pct:6.1f}% |{bar}|")

            # Right: Top talkers
            top_talkers = get_top_talkers(TOP_TALKERS)
            right_x = left_col_width + 2
            stdscr.addstr(4, right_x, "Top Talkers (sent+recv):", curses.A_UNDERLINE)
            for i, (total, ip, v) in enumerate(top_talkers):
                txt = f"{i+1:2d}. {ip:>15}  {nice_bytes(total):>8}  pkts:{v.get('pkts',0):>6}"
                stdscr.addstr(5 + i, right_x, txt[:width - right_x - 1])

            # Graph
            graph_y = max(6 + max(len(proto_snapshot), TOP_TALKERS) + 1, height - 8)
            graph_h = 6
            stdscr.addstr(graph_y - 1, 0, "-" * (width - 1))
            stdscr.addstr(graph_y, 0, "Packet-rate (most recent -> left):")
            series_pkts = [p for p, _ in series_list] + [cur_pkts]
            max_pps = max(1, max(series_pkts))
            cols = min(len(series_pkts), width - 4)
            recent = series_pkts[-cols:]
            for idx, val in enumerate(recent):
                col_x = 2 + idx
                bar_h = int((val / max_pps) * (graph_h - 1))
                for yh in range(graph_h):
                    char = " "
                    if (graph_h - yh - 1) <= bar_h:
                        char = "|"
                    stdscr.addstr(graph_y + 1 + yh, col_x, char)

            footer_y = graph_y + graph_h + 2
            stdscr.addstr(footer_y, 0, f"Captured on iface: {iface}   Total hosts tracked: {len(state.hosts)}")
            stdscr.addstr(footer_y + 1, 0,
                          f"Protocol counts sample: {', '.join(f'{k}:{v}' for k, v in list(state.protocol_counts.items())[:6])}"[:width - 1])
            stdscr.refresh()

        except curses.error:
            pass
        except Exception as e:
            sys.stderr.write(f"UI error: {e}\n")
            time.sleep(0.1)

    # --- Safe teardown ---
    try:
        if not curses.isendwin():
            curses.endwin()
    except curses.error:
        sys.stderr.write("Warning: curses termination failed (possibly non-TTY).\n")
    except Exception as e:
        sys.stderr.write(f"UI cleanup error: {e}\n")

# ---------- Helpers ----------
def detect_default_iface() -> str:
    try:
        iface = conf.iface
        if isinstance(iface, str):
            return iface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        for i in conf.ifaces:
            try:
                addr = conf.ifaces[i].ip
                if addr == local_ip:
                    return i
            except Exception:
                continue
        return list(conf.ifaces.keys())[0]
    except Exception:
        return "eth0"

def sigint_handler(signum, frame):
    state.running = False

# ---------- CLI ----------
def parse_args():
    description = (
        "PulseLine — Live Network Activity Visualizer (terminal)\n\n"
        "Captures live packets and shows rolling statistics, protocol breakdowns, "
        "and top talkers. Designed for operational awareness on Kali and Linux."
    )
    parser = argparse.ArgumentParser(
        prog="pulseline.py",
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--iface", "-i", help="Interface to capture on", default=None)
    parser.add_argument("--filter", "-f", help="BPF filter (e.g., 'tcp and port 80')", default=None)
    parser.add_argument("--top", "-t", help="Number of top talkers (default 8)", type=int, default=TOP_TALKERS)
    parser.add_argument("--window", "-w", help="Rolling window seconds (default 30)", type=int, default=ROLLING_SECONDS)
    parser.add_argument("--pps-alert", help="PPS alert threshold", type=int, default=ALERT_PPS_THRESHOLD)
    parser.add_argument("--bps-alert", help="B/s alert threshold", type=int, default=ALERT_BPS_THRESHOLD)
    parser.add_argument("--version", action="version", version="PulseLine 1.0")
    return parser.parse_args()

# ---------- Main ----------
def main():
    args = parse_args()
    global TOP_TALKERS, ROLLING_SECONDS, ALERT_PPS_THRESHOLD, ALERT_BPS_THRESHOLD
    TOP_TALKERS = args.top
    ROLLING_SECONDS = max(3, args.window)
    ALERT_PPS_THRESHOLD = args.pps_alert
    ALERT_BPS_THRESHOLD = args.bps_alert
    state.series = RollingSeries(ROLLING_SECONDS)
    iface = args.iface or detect_default_iface()
    state.iface = iface

    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)

    cap_thread = threading.Thread(target=capture_thread, args=(iface, args.filter), daemon=True)
    cap_thread.start()

    try:
        curses.wrapper(lambda stdscr: draw_ui(stdscr, iface))
    except KeyboardInterrupt:
        state.running = False
    except Exception as e:
        sys.stderr.write(f"Fatal UI error: {e}\n")
        import traceback; traceback.print_exc()
        state.running = False

    try:
        cap_thread.join(timeout=1.0)
    except Exception:
        pass

    print("\nPulseLine stopped. Exiting.")

if __name__ == "__main__":
    main()
