#!/usr/bin/env python3
"""
Surge — One-Shot Vulnerability Pattern Analyzer
Author: quicksilver
Environment: Kali Linux, Python 3
"""

import os
import sys
import re
import time
import argparse
import textwrap
from datetime import datetime

# ===============================
# Terminal Colors
# ===============================
class Color:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

# ===============================
# Vulnerability Signatures
# ===============================
SIGNATURES = [
    (r"\beval\s*\(", "Critical", "Use of eval() — remote code execution risk"),
    (r"subprocess\.Popen\s*\(.*shell\s*=\s*True", "Critical", "Shell=True in subprocess — command injection risk"),
    (r"os\.system\s*\(", "High", "os.system() execution detected"),
    (r"exec\s*\(", "High", "Use of exec() — dynamic code execution"),
    (r"pickle\.load\s*\(", "High", "Untrusted pickle loading"),
    (r"base64\.b64decode\s*\(", "Medium", "Decoding data — check for embedded secrets"),
    (r"API[_\-]?KEY\s*=\s*[\"'].*[\"']", "Critical", "Hardcoded API key detected"),
    (r"SECRET[_\-]?KEY\s*=\s*[\"'].*[\"']", "Critical", "Hardcoded secret key detected"),
    (r"password\s*=\s*[\"'].*[\"']", "High", "Hardcoded password"),
    (r"SELECT\s+.*FROM\s+.*\+\s*", "Medium", "Possible SQL injection pattern"),
    (r"input\s*\(.*\)", "Low", "User input found — ensure validation"),
    (r"hashlib\.md5\s*\(", "Medium", "Weak hash function (MD5)"),
    (r"random\.random\s*\(", "Low", "Non-cryptographic random used"),
    (r"eval_js", "Medium", "JS dynamic evaluation"),
    (r"<script>.*</script>", "Medium", "Inline scripts — XSS risk"),
]

# ===============================
# Utility Functions
# ===============================
def ascii_header():
    line = "═" * 72
    print(f"\n{Color.CYAN}{line}{Color.RESET}")
    print(f"  {Color.BOLD}CodeSurge — Vulnerability Pattern Analyzer{Color.RESET}")
    print(f"  Started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')} (UTC)")
    print(f"{Color.CYAN}{line}{Color.RESET}\n")

def progress_bar(current, total, width=40):
    ratio = current / total
    filled = int(width * ratio)
    bar = "█" * filled + "░" * (width - filled)
    print(f"\r[{bar}] {current}/{total} files", end="", flush=True)

def score_color(level):
    if level >= 80:
        return Color.RED
    elif level >= 50:
        return Color.YELLOW
    else:
        return Color.GREEN

# ===============================
# Core Scanner
# ===============================
def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
            for pattern, severity, desc in SIGNATURES:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append((severity, desc))
    except Exception:
        pass
    return findings

def scan_directory(path, exts):
    results = []
    total_files = 0
    for root, _, files in os.walk(path):
        for f in files:
            if any(f.lower().endswith(ext) for ext in exts):
                total_files += 1

    if total_files == 0:
        print(f"{Color.YELLOW}No files found matching extensions {exts}{Color.RESET}")
        return []

    count = 0
    start_time = time.time()
    for root, _, files in os.walk(path):
        for fname in files:
            if not any(fname.lower().endswith(ext) for ext in exts):
                continue
            count += 1
            fpath = os.path.join(root, fname)
            progress_bar(count, total_files)
            findings = scan_file(fpath)
            for sev, desc in findings:
                color = Color.RED if sev == "Critical" else Color.YELLOW if sev == "High" else Color.GREEN
                print(f"\n {color}[{sev}]{Color.RESET} {fpath} → {desc}")
                results.append((fpath, sev, desc))
    end_time = time.time()
    print()
    print(f"\nScan completed in {end_time - start_time:.2f}s — {total_files} files checked.\n")
    return results

# ===============================
# Report Summary
# ===============================
def summarize(results):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for _, sev, _ in results:
        if sev in counts:
            counts[sev] += 1
    total = sum(counts.values())
    if total == 0:
        print(f"{Color.GREEN}✅ No issues detected — code appears clean.{Color.RESET}")
        return 0

    score = 100 - (counts["Critical"] * 20 + counts["High"] * 10 + counts["Medium"] * 5 + counts["Low"])
    score = max(0, min(100, score))
    color = score_color(score)

    print(f"{Color.BOLD}Summary:{Color.RESET}")
    for k, v in counts.items():
        c = Color.RED if k == "Critical" else Color.YELLOW if k == "High" else Color.CYAN if k == "Medium" else Color.GREEN
        print(f"  {c}{k:<8}{Color.RESET}: {v}")
    print(f"\nSecurity Score: {color}{score}/100{Color.RESET}\n")
    return score

# ===============================
# Main Entry
# ===============================
def main():
    parser = argparse.ArgumentParser(
        prog="surge",
        description="Scan files for vulnerability patterns",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--path", "-p", required=True, help="Path to directory or file to scan")
    parser.add_argument("--extensions", "-e", default="py,sh,js,php,c,cpp,conf,env,json", help="Comma-separated file extensions to include")
    parser.add_argument("--save", "-s", help="Optional output file for summary report")

    args = parser.parse_args()
    path = os.path.abspath(args.path)
    exts = [f".{x.strip().lower()}" for x in args.extensions.split(",") if x.strip()]

    ascii_header()

    if not os.path.exists(path):
        print(f"{Color.RED}Error: path not found → {path}{Color.RESET}")
        sys.exit(1)

    results = []
    if os.path.isfile(path):
        print(f"{Color.BLUE}Scanning single file...{Color.RESET}")
        results = [(path, sev, desc) for sev, desc in scan_file(path)]
    else:
        print(f"{Color.BLUE}Scanning directory recursively: {path}{Color.RESET}")
        results = scan_directory(path, exts)

    score = summarize(results)

    # Save report if requested
    if args.save:
        try:
            with open(args.save, "w") as f:
                f.write("Surge Vulnerability Report\n")
                f.write(f"Scanned: {path}\n")
                f.write(f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}\n")
                f.write(f"Security Score: {score}/100\n\n")
                for fp, sev, desc in results:
                    f.write(f"[{sev}] {fp} → {desc}\n")
            print(f"{Color.CYAN}Report saved to {args.save}{Color.RESET}")
        except Exception as e:
            print(f"{Color.RED}Failed to save report: {e}{Color.RESET}")

    print(f"{Color.BOLD}Done.{Color.RESET}")

if __name__ == "__main__":
    main()
