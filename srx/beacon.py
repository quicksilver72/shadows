#!/usr/bin/env python3
"""
Beacon — BLE/Wi-Fi Beacon Correlator & Heatmapper
Passive beacon capture, correlation, and live terminal heatmap.
Save as: beacon.py
"""

from __future__ import annotations
import subprocess
import time
import sys
import json
import shutil
import re
import threading
from datetime import datetime
from pathlib import Path

# ======================
# Terminal color helpers
# ======================
class C:
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def color(s: str, c: str) -> str:
    return f"{c}{s}{C.RESET}"

# ======================
# Utilities
# ======================
def check_tool(name: str) -> bool:
    return shutil.which(name) is not None

def run_cmd_capture(cmd, timeout=None):
    """Run a command and yield stdout lines (non-blocking style)."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        for line in iter(proc.stdout.readline, ''):
            if not line:
                break
            yield line.rstrip("\n")
    finally:
        try:
            proc.stdout.close()
            proc.terminate()
        except Exception:
            pass
        proc.wait()

def parse_wifi_scan_output(output: str):
    """
    Parse `iw dev <iface> scan` output to find BSS and signal lines.
    Returns list of tuples (mac, rssi).
    """
    found = []
    # BSS lines: "BSS <MAC>(on <iface>)"
    # signal lines: "signal: -XX.XX dBm"
    for bss in re.split(r"\n\s*\n", output):
        m = re.search(r"BSS\s+([0-9A-F:]{17})", bss, re.I)
        if not m:
            continue
        mac = m.group(1).upper()
        r = re.search(r"signal:\s*(-?\d+)", bss)
        rssi = int(r.group(1)) if r else None
        found.append((mac, rssi))
    return found

def parse_ble_line(line: str):
    """
    Parse a single hcitool lescan or similar line for MAC and name.
    """
    m = re.search(r"([0-9A-F:]{17})\s*(.*)$", line, re.I)
    if not m:
        return None, None
    mac = m.group(1).upper()
    name = m.group(2).strip() or "Unknown"
    return mac, name

# ======================
# Beacon Core
# ======================
class Beacon:
    def __init__(self, mode: str, iface_wifi: str | None, iface_ble: str | None,
                 duration: int = 60, interval: int = 5, heatmap: bool = False,
                 correlate: bool = False, save_json: bool = False):
        self.mode = mode
        self.iface_wifi = iface_wifi
        self.iface_ble = iface_ble
        self.duration = duration
        self.interval = interval
        self.heatmap = heatmap
        self.correlate = correlate
        self.save_json = save_json
        self.wifi_data: dict[str, dict] = {}
        self.ble_data: dict[str, dict] = {}
        self.start_ts = time.time()

    def capture_wifi(self):
        if not check_tool("iw"):
            print(color("[X] Wi-Fi tool 'iw' not found", C.RED))
            return
        iface = self.iface_wifi
        if not iface:
            print(color("[X] No Wi-Fi interface specified", C.RED))
            return
        # capture snapshots using `iw dev <iface> scan`
        end = time.time() + self.duration
        while time.time() < end:
            try:
                out = subprocess.check_output(["iw", "dev", iface, "scan"], stderr=subprocess.DEVNULL, text=True, timeout=10)
            except Exception:
                # on error, wait and retry
                time.sleep(self.interval)
                continue
            for mac, rssi in parse_wifi_scan_output(out):
                self.wifi_data[mac] = {"rssi": rssi, "last_seen": datetime.utcnow().isoformat()}
            time.sleep(self.interval)

    def capture_ble(self):
        # Prefer `hcitool` if available, fallback to `bluetoothctl` scanning parse
        if check_tool("hcitool"):
            cmd = ["hcitool", "lescan"]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            except Exception:
                print(color("[X] Failed to start hcitool lescan", C.RED))
                return
            t0 = time.time()
            while time.time() - t0 < self.duration:
                line = proc.stdout.readline()
                if not line:
                    break
                mac, name = parse_ble_line(line.strip())
                if mac:
                    self.ble_data[mac] = {"name": name, "last_seen": datetime.utcnow().isoformat()}
            try:
                proc.terminate()
            except Exception:
                pass
        elif check_tool("bluetoothctl"):
            # "bluetoothctl scan on" and parse output
            try:
                p = subprocess.Popen(["bluetoothctl"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                p.stdin.write("scan on\n")
                p.stdin.flush()
            except Exception:
                print(color("[X] Failed to start bluetoothctl", C.RED))
                return
            t0 = time.time()
            while time.time() - t0 < self.duration:
                line = p.stdout.readline()
                if not line:
                    break
                mac, name = parse_ble_line(line.strip())
                if mac:
                    self.ble_data[mac] = {"name": name, "last_seen": datetime.utcnow().isoformat()}
            try:
                p.stdin.write("scan off\n")
                p.stdin.flush()
                p.terminate()
            except Exception:
                pass
        else:
            print(color("[X] No BLE scan tool found (hcitool/bluetoothctl)", C.RED))

    def correlate_sets(self):
        """Attempt to correlate BLE↔Wi-Fi by MAC equality or presence in both lists."""
        corr = []
        for mac in self.ble_data:
            if mac in self.wifi_data:
                corr.append((mac, self.ble_data[mac].get("name", "Unknown"), self.wifi_data[mac].get("rssi")))
        return corr

    def print_table(self):
        # clear screen if TTY
        if sys.stdout.isatty():
            sys.stdout.write("\033c")
        print(color("╔════════════════════════════════════════════════════════╗", C.CYAN))
        print(color("║                      B E A C O N                       ║", C.CYAN))
        print(color("╚════════════════════════════════════════════════════════╝", C.CYAN))
        print(color(f"Mode: {self.mode.upper()} | Duration: {self.duration}s | Interval: {self.interval}s", C.YELLOW))
        print("──────────────────────────────────────────────────────────")
        if self.mode in ("wifi", "both"):
            print(color("[Wi-Fi]", C.BOLD))
            if not self.wifi_data:
                print("  (no Wi-Fi beacons yet)")
            else:
                for mac, d in list(self.wifi_data.items())[:40]:
                    rssi = d.get("rssi")
                    bar = ("█" * max(1, (100 + (rssi or -100)) // 4)) if rssi is not None else ""
                    col = C.GREEN if (rssi and rssi > -60) else C.YELLOW if (rssi and rssi > -80) else C.RED
                    print(f"{mac:17} {str(rssi) + ' dBm' if rssi is not None else 'N/A':>7}  {color(bar, col)}")
            print("──────────────────────────────────────────────────────────")
        if self.mode in ("ble", "both"):
            print(color("[BLE]", C.BOLD))
            if not self.ble_data:
                print("  (no BLE beacons yet)")
            else:
                for mac, d in list(self.ble_data.items())[:40]:
                    name = d.get("name", "Unknown")
                    print(f"{mac:17} {name}")
        if self.correlate:
            corr = self.correlate_sets()
            if corr:
                print("──────────────────────────────────────────────────────────")
                print(color("[Correlations]", C.BOLD))
                for mac, name, rssi in corr:
                    print(f"{mac:17} ↔ {name:20} {str(rssi) + ' dBm' if rssi is not None else 'N/A'}")
        print("──────────────────────────────────────────────────────────")
        print(color(f"Last update: {datetime.utcnow().isoformat()}Z", C.CYAN))

    def run(self):
        print(color("[*] Starting Beacon...", C.CYAN))
        threads = []
        if self.mode in ("wifi", "both") and self.iface_wifi:
            t = threading.Thread(target=self.capture_wifi, daemon=True)
            threads.append(t)
        if self.mode in ("ble", "both") and self.iface_ble:
            t = threading.Thread(target=self.capture_ble, daemon=True)
            threads.append(t)
        # start capture threads
        for t in threads:
            t.start()
        # display loop or wait
        if self.heatmap:
            end_ts = time.time() + self.duration
            while time.time() < end_ts:
                self.print_table()
                time.sleep(self.interval)
        # join
        for t in threads:
            t.join()
        # optional JSON save
        if self.save_json:
            j = {"wifi": self.wifi_data, "ble": self.ble_data, "captured_at": datetime.utcnow().isoformat()}
            try:
                out_path = Path("/tmp/beacon.json")
                out_path.write_text(json.dumps(j, indent=2))
                print(color(f"[+] Saved summary JSON: {out_path}", C.GREEN))
            except Exception as e:
                print(color(f"[!] Failed to save JSON: {e}", C.YELLOW))
        print(color("[+] Capture complete.", C.GREEN))

# ======================
# Help / CLI
# ======================
HELP_TEXT = f"""
{C.CYAN}╔══════════════════════════════════════════════════════╗{C.RESET}
{C.CYAN}║                        B E A C O N                    ║{C.RESET}
{C.CYAN}╚══════════════════════════════════════════════════════╝{C.RESET}

Passive BLE/Wi-Fi beacon correlator and heatmapper.

Usage examples:
  sudo ./beacon.py --mode wifi  --iface wlan0mon --duration 60 --heatmap
  sudo ./beacon.py --mode ble   --iface hci0     --duration 30
  sudo ./beacon.py --mode both  --iface wlan0mon,hci0 --correlate --heatmap

Flags:
  --mode <wifi|ble|both>        Capture mode (default: wifi)
  --iface <iface[,iface2]>      Wi-Fi monitor iface and/or BLE adapter (e.g. wlan0mon,hci0)
  --duration <seconds>          Total capture duration (default: 60)
  --interval <seconds>          Screen refresh interval (default: 5)
  --heatmap                     Enable live terminal heatmap display
  --correlate                   Attempt BLE↔Wi-Fi correlation
  --save-json                   Save capture summary to /tmp/beacon.json
  --help, -h                    Show this help and exit
  --version                     Show version and exit

Notes:
  • Beacon is passive: it performs only scans and does not transmit.
  • For Wi-Fi monitoring use an interface in monitor mode (e.g. wlan0mon).
  • Running with sudo/root is recommended for full visibility.
"""

def main():
    # Early intercept for help/version
    if "--help" in sys.argv or "-h" in sys.argv:
        print(HELP_TEXT); sys.exit(0)
    if "--version" in sys.argv:
        print("Beacon v1.0 — Kali Edition"); sys.exit(0)

    # Minimal arg parsing (explicit and robust)
    mode = "wifi"
    iface = None
    duration = 60
    interval = 5
    heatmap = False
    correlate = False
    save_json = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--mode",):
            i += 1; mode = args[i]
        elif a in ("--iface",):
            i += 1; iface = args[i]
        elif a in ("--duration",):
            i += 1; duration = int(args[i])
        elif a in ("--interval",):
            i += 1; interval = int(args[i])
        elif a == "--heatmap":
            heatmap = True
        elif a == "--correlate":
            correlate = True
        elif a == "--save-json":
            save_json = True
        else:
            print(color(f"[!] Unknown argument: {a}", C.YELLOW))
        i += 1

    iface_wifi = None
    iface_ble = None
    if iface:
        if "," in iface:
            parts = [p.strip() for p in iface.split(",")]
            iface_wifi = parts[0] if len(parts) > 0 else None
            iface_ble = parts[1] if len(parts) > 1 else None
        else:
            if mode == "wifi":
                iface_wifi = iface
            elif mode == "ble":
                iface_ble = iface
            elif mode == "both":
                iface_wifi = iface
                iface_ble = "hci0"  # default BLE if not provided

    if mode not in ("wifi", "ble", "both"):
        print(color("[X] Invalid mode. Use --help to view options.", C.RED)); sys.exit(2)

    if mode in ("wifi", "both") and not iface_wifi:
        print(color("[X] Wi-Fi mode selected but no Wi-Fi interface provided (use --iface).", C.RED)); sys.exit(2)
    if mode in ("ble", "both") and not iface_ble:
        # allow auto-detection of hci0 if present
        if check_tool("hcitool") or check_tool("bluetoothctl"):
            iface_ble = iface_ble or "hci0"
        else:
            print(color("[X] BLE mode selected but no BLE tool or interface is available.", C.RED)); sys.exit(2)

    b = Beacon(mode=mode, iface_wifi=iface_wifi, iface_ble=iface_ble,
               duration=duration, interval=interval, heatmap=heatmap,
               correlate=correlate, save_json=save_json)
    b.run()

if __name__ == "__main__":
    main()
