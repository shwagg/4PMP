#!/usr/bin/env python3
"""
EKSMC - Clean implementation (encrypt/decrypt)

Usage:
  Non-interactive (preferred for automation):
      Provide stdin with:
        ------ESC------
        <plaintext>
        <passphrase>
      The program prints the JSON ciphertext package to stdout.

  Interactive:
      The script prompts:
        [1] Encrypt
        [2] Decrypt
"""

import sys
import json
import base64
import hashlib
import secrets
from typing import Tuple, List

# -------------------------
# Helpers
# -------------------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

# -------------------------
# Key derivation
# -------------------------
def derive_key(passphrase: str, salt: bytes, iterations: int = 200_000, dklen: int = 16) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=dklen)

# -------------------------
# Substitution (forward / reverse)
# -------------------------
def substitute(chars: List[str], flags: List[int], key: bytes) -> List[str]:
    out = []
    for i, ch in enumerate(chars):
        kb = key[i % len(key)]
        if flags[i] == 1 and ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            old = ord(ch) - base
            shift = kb % 26
            out.append(chr(base + ((old + shift) % 26)))
        else:
            out.append(chr((ord(ch) + kb) % 0x110000))
    return out

def reverse_substitute(chars: List[str], flags: List[int], key: bytes) -> List[str]:
    out = []
    for i, ch in enumerate(chars):
        kb = key[i % len(key)]
        if flags[i] == 1 and ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            old = ord(ch) - base
            shift = kb % 26
            out.append(chr(base + ((old - shift) % 26)))
        else:
            out.append(chr((ord(ch) - kb) % 0x110000))
    return out

# -------------------------
# Shift-merge transposition (forward / reverse)
# -------------------------
def shiftmerge_transpose(seq: List[str], key: bytes) -> List[str]:
    odds = seq[0::2]
    evens = seq[1::2]
    if evens:
        shift_amt = key[1] % len(evens)
        evens = evens[-shift_amt:] + evens[:-shift_amt]
    merged = []
    o = e = 0
    for i in range(len(seq)):
        if i % 2 == 0:
            merged.append(odds[o]); o += 1
        else:
            merged.append(evens[e]); e += 1
    return merged

def shiftmerge_untranspose(seq: List[str], key: bytes) -> List[str]:
    odds = seq[0::2]
    evens = seq[1::2]
    if evens:
        shift_amt = key[1] % len(evens)
        evens = evens[shift_amt:] + evens[:shift_amt]
    out = []
    o = e = 0
    for i in range(len(seq)):
        if i % 2 == 0:
            out.append(odds[o]); o += 1
        else:
            out.append(evens[e]); e += 1
    return out

# -------------------------
# Keystream-based XOR (SHA-256 counter mode)
# -------------------------
def keystream_xor(label: str, key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < len(plaintext):
        block = hashlib.sha256(
            key + nonce + label.encode("utf-8") + counter.to_bytes(4, "big")
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(p ^ k for p, k in zip(plaintext, out[:len(plaintext)]))

# -------------------------
# High-level encrypt/decrypt
# -------------------------
def encrypt(plaintext: str, passphrase: str) -> dict:
    salt = secrets.token_bytes(16)
    key = derive_key(passphrase, salt)
    nonce = secrets.token_bytes(12)

    compact_chars = []
    space_positions = []
    flags = []

    for ch in plaintext:
        if ch == " ":
            space_positions.append(len(compact_chars))
        else:
            compact_chars.append(ch)
            flags.append(1 if ch.isalpha() else 0)

    substituted = substitute(compact_chars, flags, key)
    transposed = shiftmerge_transpose(substituted, key)
    main_bytes = "".join(transposed).encode("utf-8")

    sp_bytes = ",".join(map(str, space_positions)).encode("utf-8")
    fl_bytes = bytes(flags)

    sp_enc = keystream_xor("space", key, nonce, sp_bytes)
    fl_enc = keystream_xor("flags", key, nonce, fl_bytes)

    noiseL = secrets.token_bytes(3)
    noiseR = secrets.token_bytes(3)

    return {
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "main_cipher": b64e(main_bytes),
        "noiseL": b64e(noiseL),
        "space_enc": b64e(sp_enc),
        "flags_enc": b64e(fl_enc),
        "noiseR": b64e(noiseR),
    }

def decrypt(package_json: str, passphrase: str) -> str:
    pkg = json.loads(package_json)

    salt = b64d(pkg["salt"])
    nonce = b64d(pkg["nonce"])
    key = derive_key(passphrase, salt)

    sp_enc = b64d(pkg["space_enc"])
    fl_enc = b64d(pkg["flags_enc"])
    main_bytes = b64d(pkg["main_cipher"])

    sp_bytes = keystream_xor("space", key, nonce, sp_enc)
    fl_bytes = keystream_xor("flags", key, nonce, fl_enc)

    space_positions = list(map(int, sp_bytes.decode("utf-8").split(","))) if sp_bytes else []
    flags = list(fl_bytes)

    transposed = list(main_bytes.decode("utf-8"))
    untransposed = shiftmerge_untranspose(transposed, key)
    reversed_sub = reverse_substitute(untransposed, flags, key)

    result = reversed_sub[:]
    for pos in space_positions:
        if 0 <= pos <= len(result):
            result.insert(pos, " ")

    return "".join(result)

# -------------------------
# CLI / stdin parsing
# -------------------------
def parse_stdin_block() -> Tuple[str, str]:
    data = sys.stdin.read().splitlines()
    try:
        i = data.index("------ESC------")
    except ValueError:
        return None, None
    plaintext = data[i + 1] if i + 1 < len(data) else ""
    passphrase = data[i + 2] if i + 2 < len(data) else ""
    return plaintext, passphrase

def main():
    plaintext, passphrase = parse_stdin_block()

    if plaintext and passphrase:
        package = encrypt(plaintext, passphrase)
        print(json.dumps(package))
        return

    while True:
        print("\n=== EKSMC ===")
        print("[1] Encrypt")
        print("[2] Decrypt")
        print("[3] Exit")
        choice = input("Choose: ").strip()

        if choice == "3":
            return

        if choice == "1":
            plaintext = input("Enter plaintext: ")
            passphrase = input("Enter passphrase: ")
            pkg = encrypt(plaintext, passphrase)
            print("\nCiphertext package:\n")
            print(json.dumps(pkg, indent=2))

        elif choice == "2":
            package_json = input("Paste ciphertext package JSON: ")
            passphrase = input("Enter passphrase: ")
            try:
                result = decrypt(package_json, passphrase)
                print("\nDecrypted plaintext:\n")
                print(result)
            except Exception as e:
                print("Decryption failed:", e)

        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
