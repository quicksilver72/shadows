#!/usr/bin/env python3
"""
KeyPro — Modular Password & Key Generator
Author: quicksilver

A secure, interactive key generator for cybersecurity, networking, and
pentesting professionals. Uses cryptographically strong randomness, 
entropy measurement, and multiple generation profiles.
"""

import os
import sys
import argparse
import secrets
import string
import textwrap
import math
import datetime
import cmd

# ==========================================================
# ASCII Header + Utility
# ==========================================================
def ascii_header(title: str):
    line = "═" * 72
    print(f"\n\033[36m{line}\033[0m")
    print(f"  \033[1m{title}\033[0m")
    print(f"  Started: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}")
    print(f"\033[36m{line}\033[0m\n")

def entropy(bits: int) -> float:
    """Convert entropy bits into a normalized score (0–100)."""
    return min(100.0, round(bits / 1.28, 2))  # ~128 bits ≈ 100%

def entropy_bar(bits: int):
    """Generate an ASCII entropy bar visualization."""
    score = int(entropy(bits) / 4)
    filled = "█" * score
    empty = "░" * (25 - score)
    return f"[{filled}{empty}] {bits:.1f} bits"

# ==========================================================
# Key Generation Profiles
# ==========================================================
def gen_password(length: int) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def gen_high_entropy(length: int) -> str:
    """Generate high-entropy hexadecimal key."""
    byte_count = math.ceil(length / 2)
    return secrets.token_hex(byte_count)[:length]

def gen_api_key(length: int) -> str:
    """Generate Base64-like key with alphanumeric and dash/underscore."""
    chars = string.ascii_letters + string.digits + "-_"
    return ''.join(secrets.choice(chars) for _ in range(length))

def gen_memorable(words: int = 4) -> str:
    """Generate semi-pronounceable passphrase-style key."""
    syllables = ["ka", "zo", "mi", "ta", "ra", "po", "li", "nu", "si", "ve", "xo", "qu", "da", "te"]
    return '-'.join(''.join(secrets.choice(syllables) for _ in range(2)) for _ in range(words))

def gen_custom(template: str) -> str:
    """Generate custom patterned keys (X=upper, x=lower, #=digit, *=symbol)."""
    sym = "!@#$%^&*"
    out = ""
    for c in template:
        if c == "X":
            out += secrets.choice(string.ascii_uppercase)
        elif c == "x":
            out += secrets.choice(string.ascii_lowercase)
        elif c == "#":
            out += secrets.choice(string.digits)
        elif c == "*":
            out += secrets.choice(sym)
        else:
            out += c
    return out

# ==========================================================
# Interactive Shell
# ==========================================================
class KeyProShell(cmd.Cmd):
    intro = "KeyPro — interactive key forge. Type 'help' for commands.\n"
    prompt = "keypro> "

    def __init__(self):
        super().__init__()
        ascii_header("KeyPro — Secure Key Forge")
        print("Available commands: gen, list, clear, help, exit\n")
        self.generated = []  # in-memory only

    def do_exit(self, arg):
        "Exit KeyPro."
        print("Exiting KeyPro.")
        return True

    def do_quit(self, arg):
        return self.do_exit(arg)

    def do_clear(self, arg):
        "Clear all generated keys from memory."
        self.generated.clear()
        print("[*] All generated keys cleared from memory.")

    def do_list(self, arg):
        "List previously generated keys in this session."
        if not self.generated:
            print("(No keys generated yet.)")
            return
        for i, (label, key, bits) in enumerate(self.generated, start=1):
            print(f"{i:2d}. {label:<12} {key}  |  Entropy: {bits:.1f} bits")

    # -----------------------------
    # Generation Commands
    # -----------------------------
    def do_gen(self, arg):
        """
        Generate a new key.
        Usage:
          gen password <length>
          gen high <length>
          gen api <length>
          gen memorable <words>
          gen custom "<template>"

        Examples:
          gen password 16
          gen api 64
          gen high 32
          gen memorable 4
          gen custom "XX-##-xx"
        """
        args = arg.split()
        if not args:
            print("Usage: gen <profile> [args...] (type 'help gen' for options)")
            return

        profile = args[0].lower()
        key = None
        bits = 0

        try:
            if profile == "password":
                length = int(args[1])
                key = gen_password(length)
                bits = length * math.log2(len(string.ascii_letters + string.digits + "!@#$%^&*()-_=+"))
            elif profile == "high":
                length = int(args[1])
                key = gen_high_entropy(length)
                bits = length * 4  # approx 4 bits per hex char
            elif profile == "api":
                length = int(args[1])
                key = gen_api_key(length)
                bits = length * math.log2(len(string.ascii_letters + string.digits + "-_"))
            elif profile == "memorable":
                words = int(args[1]) if len(args) > 1 else 4
                key = gen_memorable(words)
                bits = words * 16  # approx
            elif profile == "custom":
                template = ' '.join(args[1:]).strip('"')
                key = gen_custom(template)
                bits = len(key) * 5.5  # heuristic
            else:
                print("Unknown profile. Valid: password, high, api, memorable, custom")
                return
        except Exception as e:
            print("Error:", e)
            return

        # Display results
        self.generated.append((profile, key, bits))
        print(f"\nGenerated ({profile}):\n{key}\n")
        print("Entropy:", entropy_bar(bits))

# ==========================================================
# CLI Entry Point
# ==========================================================
def show_help():
    ascii_header("KeyPro Help — Modular Password & Key Generator")
    print(textwrap.dedent("""
    Usage:
      keypro               Launch interactive shell
      keypro --help        Show this help message
      keypro --version     Show version info

    Description:
      KeyPro is a secure interactive key forge for generating
      cryptographically strong passwords and tokens. 
      It supports five generation profiles:

      • password   — Random complex password
      • high       — High-entropy hexadecimal key
      • api        — Base64-style API key
      • memorable  — Pronounceable word-based key
      • custom     — Pattern-defined key (X=Upper, x=Lower, #=Digit, *=Symbol)

    Example:
      keypro> gen password 16
      keypro> gen api 64
      keypro> gen custom "XX-##-xx"
      keypro> list

    Security:
      • Keys exist only in memory for this session.
      • No exports, clipboard, or persistent storage.
      • Uses os.urandom() + secrets for cryptographic strength.
    """))

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--help", "-h", action="store_true")
    parser.add_argument("--version", "-v", action="store_true")
    args = parser.parse_args()

    if args.help:
        show_help()
        sys.exit(0)

    if args.version:
        print("KeyPro v1.0 — Secure Key Forge (Kali Edition)")
        sys.exit(0)

    shell = KeyProShell()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nInterrupted — exiting.")

if __name__ == "__main__":
    main()
