#!/usr/bin/env python3

import os
import sys
import binascii
from base64 import b64encode, b64decode
from getpass import getpass
from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ==========================
# Core Cryptographic Helpers
# ==========================

def create_salt(length: int = 16) -> bytes:
    """Generate a random salt of given length."""
    return os.urandom(length)

def hash_password(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """
    Derive a secure hash using PBKDF2-HMAC-SHA512.
    Returns derived key bytes suitable for storage or further key material.
    """
    return pbkdf2_hmac('sha512', password.encode(), salt, iterations, dklen=64)

def verify_password(stored_hash: bytes, password: str, salt: bytes, iterations: int = 200_000) -> bool:
    """Verify a password against a stored PBKDF2 hash."""
    test_hash = hash_password(password, salt, iterations)
    return hmac_compare(stored_hash, test_hash)

def hmac_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to mitigate timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

def generate_key(length: int = 32) -> bytes:
    """Generate a fresh symmetric AES-256 key."""
    return os.urandom(length)

# ==========================
# AES Encryption / Decryption
# ==========================

def encrypt_data(plaintext: str, key: bytes) -> str:
    """
    Encrypt plaintext using AES-256-GCM.
    Returns base64 encoded ciphertext (nonce + tag + ciphertext).
    """
    nonce = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    combined = nonce + encryptor.tag + ciphertext
    return b64encode(combined).decode()

def decrypt_data(encoded_ciphertext: str, key: bytes) -> str:
    """
    Decrypt AES-256-GCM ciphertext.
    Returns plaintext if authentication succeeds.
    """
    try:
        raw = b64decode(encoded_ciphertext)
        nonce, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        ).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
    except Exception as e:
        print("Decryption failed:", str(e))
        return None

# ==========================
# CLI Interface
# ==========================

def main():
    print("=== EZ Hash Tool ===")
    while True:
        print("\nSelect an action:")
        print("1. Hash a string")
        print("2. Verify a hashed string")
        print("3. Generate AES key")
        print("4. Encrypt data using key")
        print("5. Decrypt data using key")
        print("6. Exit")

        try:
            choice = int(input("\nEnter your choice (1–6): "))
        except ValueError:
            print("Invalid input. Enter a number between 1 and 6.")
            continue

        if choice == 6:
            print("Exiting program...")
            sys.exit(0)

        elif choice == 1:
            pwd = getpass("Enter string to hash: ")
            salt = create_salt()
            hashed = hash_password(pwd, salt)
            print("\nPassword hashed successfully.")
            print(f"Salt (hex): {binascii.hexlify(salt).decode()}")
            print(f"Hash (hex): {binascii.hexlify(hashed).decode()}")

        elif choice == 2:
            salt_hex = input("Enter stored salt (hex): ").strip()
            hash_hex = input("Enter stored hash (hex): ").strip()
            pwd = getpass("Enter string to verify: ")
            salt = binascii.unhexlify(salt_hex)
            stored_hash = binascii.unhexlify(hash_hex)
            if verify_password(stored_hash, pwd, salt):
                print("\n✅ Password verified successfully.")
            else:
                print("\n❌ Password verification failed.")

        elif choice == 3:
            key = generate_key()
            print("\nNew symmetric AES-256 key generated:")
            print(binascii.hexlify(key).decode())

        elif choice == 4:
            key_hex = getpass("Enter AES key (hex): ").strip()
            plaintext = input("Enter plaintext to encrypt: ")
            key = binascii.unhexlify(key_hex)
            ciphertext = encrypt_data(plaintext, key)
            print("\nEncrypted text (base64):")
            print(ciphertext)

        elif choice == 5:
            key_hex = getpass("Enter AES key (hex): ").strip()
            ciphertext = input("Enter base64 ciphertext: ")
            key = binascii.unhexlify(key_hex)
            plaintext = decrypt_data(ciphertext, key)
            if plaintext is not None:
                print("\nDecrypted text:")
                print(plaintext)
            else:
                print("Decryption failed or key invalid.")

        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
