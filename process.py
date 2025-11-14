#!/usr/bin/env python3
import os
import json
import base64
import hashlib
import secrets

# ============================================================
#   UTILITY FUNCTIONS
# ============================================================

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s)
# ------------------------------------------------------------
#   KEY DERIVATION (PBKDF2 → 128-bit key)
# ------------------------------------------------------------

def derive_128bit_key(passphrase: str, salt: bytes):
    key = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        200_000,
        dklen=16
    )
    return key

# ------------------------------------------------------------
#   KEYED SUBSTITUTION
# ------------------------------------------------------------

def substitute_chars(chars, flags, key, verbose=False):
    out = []
    for i, ch in enumerate(chars):
        kb = key[i % 16]

        if flags[i] == 1 and ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            old = ord(ch) - base
            shift = kb % 26
            new_val = (old + shift) % 26
            new_char = chr(base + new_val)

            if verbose:
                print(f" idx {i:2d} '{ch}'  key={kb} shift={shift:2d} -> '{new_char}'")

            out.append(new_char)

        else:
            shifted = (ord(ch) + kb) % 65536
            new_char = chr(shifted)

            if verbose:
                print(f" idx {i:2d} '{ch}'  key={kb} NONLETTER -> '{new_char}'")

            out.append(new_char)

    return out

# ------------------------------------------------------------
#   REVERSE SUBSTITUTION
# ------------------------------------------------------------

def reverse_substitute(chars, flags, key):
    out = []
    for i, ch in enumerate(chars):
        kb = key[i % 16]

        if flags[i] == 1 and ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            old = ord(ch) - base
            shift = kb % 26
            new_val = (old - shift) % 26
            new_char = chr(base + new_val)
            out.append(new_char)
        else:
            old_code = (ord(ch) - kb) % 65536
            out.append(chr(old_code))

    return out

# ------------------------------------------------------------
#   SHIFT-MERGE TRANSPOSITION
# ------------------------------------------------------------

def shiftmerge_transpose(lst, key, verbose=False):
    odds = lst[0::2]
    evens = lst[1::2]

    if len(evens) > 0:
        shift_amt = key[1] % len(evens)
        evens = evens[-shift_amt:] + evens[:-shift_amt]
    else:
        shift_amt = 0

    if verbose:
        print(" odd:", odds)
        print(" even:", evens)
        print(" shift amount:", shift_amt)

    merged = []
    o = 0
    e = 0
    for i in range(len(lst)):
        if i % 2 == 0:
            merged.append(odds[o])
            o += 1
        else:
            merged.append(evens[e])
            e += 1

    return merged

# ------------------------------------------------------------
#   REVERSE TRANSPOSE
# ------------------------------------------------------------

def shiftmerge_untranspose(lst, key):
    n = len(lst)
    odds = lst[0::2]
    evens = lst[1::2]

    if len(evens) > 0:
        shift_amt = key[1] % len(evens)
        evens = evens[shift_amt:] + evens[:shift_amt]

    out = []
    o = 0
    e = 0
    for i in range(n):
        if i % 2 == 0:
            out.append(odds[o])
            o += 1
        else:
            out.append(evens[e])
            e += 1

    return out

# ------------------------------------------------------------
#   XOR KEYSTREAM FOR METADATA ENCRYPTION
# ------------------------------------------------------------

def keystream_xor(label: str, key: bytes, nonce: bytes, plaintext: bytes):
    out = bytearray()
    counter = 0
    while len(out) < len(plaintext):
        block = hashlib.sha256(
            key + nonce + label.encode() + counter.to_bytes(4, "big")
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(p ^ k for (p, k) in zip(plaintext, out[: len(plaintext)]))

# ============================================================
#   ENCRYPTION (VERBOSE)
# ============================================================

def eksmc_encrypt_verbose(plaintext: str, passphrase: str):
    print("Plaintext:", plaintext)
    salt = secrets.token_bytes(16)
    print("Salt:", b64e(salt))

    key = derive_128bit_key(passphrase, salt)
    print("Derived key (hex):", key.hex())

    nonce = secrets.token_bytes(12)
    print("Nonce:", b64e(nonce))

    compact = []
    space_positions = []
    flags = []

    for idx, ch in enumerate(plaintext):
        if ch == " ":
            space_positions.append(len(compact))
        else:
            compact.append(ch)
            flags.append(1 if ch.isalpha() else 0)

    print("\nCompacted characters:", compact)
    print("Space positions:", space_positions)
    print("Flags:", flags)

    print("\n--- SUBSTITUTION ---")
    substituted = substitute_chars(compact, flags, key, verbose=True)

    print("\n--- TRANSPOSITION ---")
    transposed = shiftmerge_transpose(substituted, key, verbose=True)

    main_cipher_bytes = "".join(transposed).encode("utf-8")
    main_cipher_b64 = b64e(main_cipher_bytes)

    sp_bytes = ",".join(map(str, space_positions)).encode()
    fl_bytes = bytes(flags)

    space_enc = keystream_xor("space", key, nonce, sp_bytes)
    flags_enc = keystream_xor("flags", key, nonce, fl_bytes)

    noiseL = secrets.token_bytes(3)
    noiseR = secrets.token_bytes(3)

    package = {
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "main_cipher": main_cipher_b64,
        "noiseL": b64e(noiseL),
        "space_enc": b64e(space_enc),
        "flags_enc": b64e(flags_enc),
        "noiseR": b64e(noiseR),
    }

    return json.dumps(package), key, salt

# ============================================================
#   DECRYPTION (VERBOSE)
# ============================================================

def eksmc_decrypt_verbose(package_json: str, passphrase: str):
    pkg = json.loads(package_json)

    salt = b64d(pkg["salt"])
    nonce = b64d(pkg["nonce"])
    key = derive_128bit_key(passphrase, salt)

    print("Derived key (hex):", key.hex())

    space_enc = b64d(pkg["space_enc"])
    flags_enc = b64d(pkg["flags_enc"])
    main_bytes = b64d(pkg["main_cipher"])

    sp_bytes = keystream_xor("space", key, nonce, space_enc)
    fl_bytes = keystream_xor("flags", key, nonce, flags_enc)

    space_positions = list(map(int, sp_bytes.decode().split(","))) if sp_bytes else []
    flags = list(fl_bytes)

    print("Recovered space positions:", space_positions)
    print("Recovered flags:", flags)

    transposed = list(main_bytes.decode("utf-8"))
    untransposed = shiftmerge_untranspose(transposed, key)

    reversed_sub = reverse_substitute(untransposed, flags, key)

    result = reversed_sub[:]
    for pos in space_positions:
        result.insert(pos, " ")

    return "".join(result)

# ============================================================
#   INTERACTIVE MENU (VERSION B)
# ============================================================

def main():
    while True:
        print("\n=== Enhanced Keyed Shift-Merge Cipher (EKSMC) ===")
        print("[1] Encrypt plaintext")
        print("[2] Decrypt ciphertext package")
        print("[3] Exit")

        choice = input("Choose: ").strip()
        if choice == "3":
            print("Goodbye!")
            break

        passphrase = input("Enter passphrase: ").strip()

        if choice == "1":
            plaintext = input("Enter plaintext: ").strip()
            print("\n--- ENCRYPTING ---\n")
            package_json, key, salt = eksmc_encrypt_verbose(plaintext, passphrase)
            print("\n=== FINAL CIPHERTEXT PACKAGE ===\n")
            print(package_json)

        elif choice == "2":
            print("\nPaste ciphertext package JSON:")
            package_json = input().strip()
            print("\n--- DECRYPTING ---\n")
            result = eksmc_decrypt_verbose(package_json, passphrase)
            print("\n=== FINAL PLAINTEXT ===\n")
            print(result)

        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
