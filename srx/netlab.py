#!/usr/bin/env python3
"""
NetLab — Ephemeral Local Server Generator

This script prepares and runs ephemeral local test servers (HTTP, SMTP, DNS echo, etc.)
with optional isolation via podman or firejail. It is intended for safe, local testing
and training within isolated environments. By default servers bind to 127.0.0.1 only.

Usage:
  ./netlab.py --scenario static-http --method none --port 8000
  ./netlab.py --scenario vuln-http --method podman --port 8080 --timeout 300
  ./netlab.py --help

Author: quicksilver
"""

from __future__ import annotations
import argparse
import os
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ---------------------------
# Visual / terminal helpers
# ---------------------------
class C:
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def color(s: str, col: str) -> str:
    return f"{col}{s}{C.RESET}"

def info(s: str):
    print(color("[*] ", C.CYAN) + s)

def warn(s: str):
    print(color("[!] ", C.YELLOW) + s)

def ok(s: str):
    print(color("[+] ", C.GREEN) + s)

def fail(s: str):
    print(color("[X] ", C.RED) + s)

def get_now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def check_program(name: str) -> bool:
    return shutil.which(name) is not None

def is_port_free(port: int, bind_addr: str = "127.0.0.1") -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((bind_addr, port))
            return True
    except OSError:
        return False

# ---------------------------
# Scenario templates (server scripts)
# ---------------------------
STATIC_HTTP_PY = r'''#!/usr/bin/env python3
# Simple static file server (binds to 127.0.0.1)
import http.server, socketserver, os, sys
from datetime import datetime
PORT = {port}
ADDR = "127.0.0.1"
os.chdir("{serve_dir}")
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[HTTP] " + fmt % args)
with socketserver.TCPServer((ADDR, PORT), Handler) as httpd:
    print(f"Serving static files from {os.getcwd()} at http://{ADDR}:{PORT}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
'''

VULN_HTTP_PY = r'''#!/usr/bin/env python3
# Vulnerable-like echo server (for testing) — do not expose publicly.
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse, json, socket
ADDR = "127.0.0.1"
PORT = {port}
class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        self.send_response(code)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())
    def do_GET(self):
        qs = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(qs)
        body = {{
            "path": self.path,
            "client": self.client_address[0],
            "params": params
        }}
        print("[VULN-HTTP] GET", self.path)
        self._send(200, body)
    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        data = self.rfile.read(length) if length else b''
        body = {{
            "path": self.path,
            "client": self.client_address[0],
            "posted": data.decode(errors='replace')
        }}
        print("[VULN-HTTP] POST", self.path, "len=", len(data))
        self._send(200, body)
if __name__ == '__main__':
    srv = HTTPServer((ADDR, PORT), Handler)
    print(f"Vuln-HTTP listening on http://{ADDR}:{PORT}/")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
'''

SMTP_HONEYPOT_PY = r'''#!/usr/bin/env python3
# Minimal SMTP responder (for testing only) — binds to 127.0.0.1
import smtpd, asyncore, sys, socket
class TrapSMTP(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        print(f"[SMTP] mail from={mailfrom} rcpt={rcpttos} size={len(data)}")
        return
ADDR = "127.0.0.1"
PORT = {port}
server = TrapSMTP((ADDR, PORT), None)
print(f"SMTP honeypot listening on {ADDR}:{PORT}")
try:
    asyncore.loop()
except KeyboardInterrupt:
    pass
'''

DNS_ECHO_PY = r'''#!/usr/bin/env python3
# Minimal DNS echo responder (UDP) — bind to 127.0.0.1
import socket, sys
ADDR = "127.0.0.1"
PORT = {port}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ADDR, PORT))
print(f"DNS echo listening on {ADDR}:{PORT} (UDP)")
try:
    while True:
        data, addr = sock.recvfrom(4096)
        print(f"[DNS] Request {len(data)} bytes from {addr}")
except KeyboardInterrupt:
    pass
'''

SCENARIOS = {
    "static-http": STATIC_HTTP_PY,
    "vuln-http": VULN_HTTP_PY,
    "smtp-honeypot": SMTP_HONEYPOT_PY,
    "dns-echo": DNS_ECHO_PY,
}

# ---------------------------
# NetLab Runtime
# ---------------------------
class NetLab:
    def __init__(self, scenario: str, method: str, port: int, timeout: Optional[int],
                 detached: bool, dry: bool, serve_dir: Optional[str]):
        self.scenario = scenario
        self.method = method
        self.port = port
        self.timeout = timeout
        self.detached = detached
        self.dry = dry
        self.serve_dir = serve_dir
        self.tmpdir = None
        self.child_proc: Optional[subprocess.Popen] = None
        self._stop_flag = False

    def prepare(self):
        info(f"Preparing scenario '{self.scenario}' using method '{self.method}' on 127.0.0.1:{self.port}")
        if self.scenario not in SCENARIOS:
            fail(f"Unknown scenario: {self.scenario}")
            sys.exit(2)
        if not is_port_free(self.port):
            fail(f"Port {self.port} is already in use on 127.0.0.1. Choose a different port.")
            sys.exit(2)
        if self.method == "podman" and not check_program("podman"):
            fail("podman not found in PATH; install podman or choose another method.")
            sys.exit(2)
        if self.method == "firejail" and not check_program("firejail"):
            fail("firejail not found in PATH; install firejail or choose another method.")
            sys.exit(2)
        # create temp dir with server script
        self.tmpdir = Path(tempfile.mkdtemp(prefix="netlab_"))
        info(f"Created temporary working dir: {self.tmpdir}")
        # write scenario script
        script = SCENARIOS[self.scenario].format(port=self.port, serve_dir=(self.serve_dir or str(self.tmpdir)))
        script_path = self.tmpdir / "server.py"
        script_path.write_text(script, encoding="utf-8")
        script_path.chmod(0o700)
        # For static-http, create an index file if serve_dir provided or temp
        if self.scenario == "static-http":
            serve_path = Path(self.serve_dir) if self.serve_dir else self.tmpdir
            Path(serve_path).mkdir(parents=True, exist_ok=True)
            (Path(serve_path) / "index.html").write_text(f"<html><body><h1>NetLab static at {get_now_iso()}</h1></body></html>")
            info(f"Prepared static files in: {serve_path}")
            self.serve_dir = str(serve_path)
        info("Preparation complete.")

    def _run_local(self):
        script_path = str(self.tmpdir / "server.py")
        cmd = [sys.executable, script_path]
        info(f"Launching local server: {' '.join(cmd)}")
        if self.dry:
            warn("Dry-run enabled; not starting local server.")
            return
        self.child_proc = subprocess.Popen(cmd, cwd=str(self.tmpdir), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            def reader():
                assert self.child_proc
                for line in self.child_proc.stdout:
                    print(color("[srv] ", C.CYAN) + line.rstrip())
            t = threading.Thread(target=reader, daemon=True)
            t.start()
            start = time.time()
            while True:
                if self.timeout and (time.time() - start) >= self.timeout:
                    warn(f"Timeout reached ({self.timeout}s); stopping server.")
                    self.stop()
                    break
                if self._stop_flag:
                    break
                if self.child_proc.poll() is not None:
                    ok("Server process exited.")
                    break
                time.sleep(0.2)
        except KeyboardInterrupt:
            warn("Interrupted by user — stopping server.")
            self.stop()

    def _run_firejail(self):
        script_path = str(self.tmpdir / "server.py")
        cmd = ["firejail", "--private=" + str(self.tmpdir), sys.executable, script_path]
        info(f"Launching server inside firejail: {' '.join(cmd)}")
        if self.dry:
            warn("Dry-run enabled; not starting firejail server.")
            return
        self.child_proc = subprocess.Popen(cmd, cwd=str(self.tmpdir), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            for line in self.child_proc.stdout:
                print(color("[fj] ", C.YELLOW) + line.rstrip())
        except KeyboardInterrupt:
            warn("Interrupted by user — stopping firejail server.")
            self.stop()

    def _run_podman(self):
        script_path = "/srv/server.py"
        local_dir = str(self.tmpdir)
        cmd = [
            "podman", "run", "--rm",
            "-v", f"{local_dir}:/srv:Z",
            "--publish", f"127.0.0.1:{self.port}:{self.port}",
            "docker.io/library/python:3.11-slim",
            "python", script_path
        ]
        info(f"Launching server inside podman (image python:3.11-slim): {' '.join(cmd)}")
        if self.dry:
            warn("Dry-run enabled; not starting podman container.")
            return
        try:
            self.child_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in self.child_proc.stdout:
                print(color("[podman] ", C.CYAN) + line.rstrip())
        except KeyboardInterrupt:
            warn("Interrupted by user — stopping container.")
            self.stop()

    def run(self):
        try:
            self.prepare()
            ok(f"Scenario ready. Server will bind to 127.0.0.1:{self.port}")
            if self.dry:
                info("Dry-run: no server started. Temporary folder would be removed now.")
                self.cleanup()
                return
            if self.detached:
                info("Detached mode requested: starting server in background.")
                if self.method == "none":
                    cmd = [sys.executable, str(self.tmpdir / "server.py")]
                    proc = subprocess.Popen(cmd, cwd=str(self.tmpdir))
                    ok(f"Server started (pid {proc.pid}) in background. Tempdir: {self.tmpdir}")
                    return
                elif self.method == "podman":
                    cmd = [
                        "podman", "run", "--rm", "-d",
                        "-v", f"{str(self.tmpdir)}:/srv:Z",
                        "--publish", f"127.0.0.1:{self.port}:{self.port}",
                        "docker.io/library/python:3.11-slim", "python", "/srv/server.py"
                    ]
                    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if proc.returncode == 0:
                        ok(f"Podman container started detached: {proc.stdout.strip()}")
                    else:
                        fail(f"Podman failed to start detached: {proc.stderr.strip()}")
                    return
                elif self.method == "firejail":
                    cmd = ["firejail", "--private=" + str(self.tmpdir), sys.executable, str(self.tmpdir / "server.py")]
                    proc = subprocess.Popen(cmd, cwd=str(self.tmpdir))
                    ok(f"Firejail started detached (pid {proc.pid}).")
                    return
            if self.method == "none":
                self._run_local()
            elif self.method == "podman":
                self._run_podman()
            elif self.method == "firejail":
                self._run_firejail()
            else:
                fail(f"Unknown method: {self.method}")
        finally:
            self.cleanup()

    def stop(self):
        self._stop_flag = True
        if self.child_proc and self.child_proc.poll() is None:
            try:
                self.child_proc.terminate()
                time.sleep(1)
                if self.child_proc.poll() is None:
                    self.child_proc.kill()
            except Exception:
                pass
            ok("Server process terminated.")

    def cleanup(self):
        try:
            if self.child_proc and self.child_proc.poll() is None:
                warn("Cleaning up: terminating child process.")
                self.stop()
        except Exception:
            pass
        try:
            if self.tmpdir and self.tmpdir.exists():
                shutil.rmtree(self.tmpdir)
                info(f"Removed temporary working dir: {self.tmpdir}")
        except Exception as e:
            warn(f"Failed to remove temporary dir {self.tmpdir}: {e}")

# ---------------------------
# CLI & Help (early intercept)
# ---------------------------
HELP_TEXT = f"""
{C.CYAN}╔════════════════════════════════════════════════════════════════╗{C.RESET}
{C.CYAN}║                          N E T L A B                           ║{C.RESET}
{C.CYAN}╚════════════════════════════════════════════════════════════════╝{C.RESET}

NetLab — Ephemeral Local Server Generator

Purpose:
  Create isolated, ephemeral local servers for testing and training.
  Servers bind to 127.0.0.1 by default. Use isolation (--method podman/firejail)
  when you need extra containment.

Quick examples:
  # Static HTTP locally (foreground)
  ./netlab.py --scenario static-http --method none --port 8000

  # Vulnerable-like HTTP inside podman for 5 minutes
  sudo ./netlab.py --scenario vuln-http --method podman --port 8080 --timeout 300

  # SMTP honeypot in firejail
  ./netlab.py --scenario smtp-honeypot --method firejail --port 2525

  # Dry-run (prepare but do not start)
  ./netlab.py --scenario static-http --method none --port 8000 --dry

Flags reference:
  --scenario, -s   Which scenario to run: {', '.join(SCENARIOS.keys())}
  --method, -m     Execution method: none | podman | firejail  (default: none)
  --port, -p       Host port to bind on 127.0.0.1 (required in run mode)
  --timeout, -t    Auto-stop after N seconds (0 = run until manually stopped)
  --detached, -d   Run server detached (background) and exit (user cleans up)
  --dry            Dry-run: create temp files but do not start server
  --serve-dir      For static-http: directory to serve (default: tempdir)
  --help, -h       Show this help and exit
  --version        Show version and exit

Safety notes:
 - Default bind address is 127.0.0.1 (local-only). Do not change unless intentional.
 - Use --method podman/firejail for added process/filesystem isolation.
 - Detached mode will not auto-clean temporary directories.
 - Containers use python:3.11-slim image from docker.io by default (podman).
"""

def build_parser():
    p = argparse.ArgumentParser(prog="netlab", add_help=False)
    p.add_argument("--scenario", "-s", choices=list(SCENARIOS.keys()))
    p.add_argument("--method", "-m", choices=["none", "podman", "firejail"], default="none")
    p.add_argument("--port", "-p", type=int)
    p.add_argument("--timeout", "-t", type=int, default=0)
    p.add_argument("--detached", "-d", action="store_true")
    p.add_argument("--dry", action="store_true")
    p.add_argument("--serve-dir")
    p.add_argument("--help", "-h", action="store_true")
    p.add_argument("--version", action="store_true")
    return p

def show_help_and_exit():
    print(HELP_TEXT)
    sys.exit(0)

# ---------------------------
# Main
# ---------------------------
def main():
    # Early intercept for --help and --version so help prints without required args
    if "--help" in sys.argv or "-h" in sys.argv:
        show_help_and_exit()
    if "--version" in sys.argv:
        print("NetLab v1.0 — Kali Edition")
        sys.exit(0)

    parser = build_parser()
    args = parser.parse_args()

    # Validate required run-time args (we now enforce them after help)
    if not args.scenario or not args.port:
        fail("Runtime error: --scenario and --port are required for starting a server. Run --help for usage.")
        sys.exit(2)

    info("NetLab starting")
    info(f"Time: {get_now_iso()}")

    nl = NetLab(scenario=args.scenario, method=args.method, port=args.port,
                timeout=(args.timeout if args.timeout > 0 else None),
                detached=args.detached, dry=args.dry, serve_dir=args.serve_dir)

    # Setup signal handler to stop gracefully
    def _sigint(sig, frame):
        warn("SIGINT received — stopping server and cleaning up.")
        nl.stop()
    signal.signal(signal.SIGINT, _sigint)
    def _sigterm(sig, frame):
        warn("SIGTERM received — stopping server and cleaning up.")
        nl.stop()
    signal.signal(signal.SIGTERM, _sigterm)

    nl.run()
    ok("NetLab finished (temporary resources cleaned)")

if __name__ == "__main__":
    main()
