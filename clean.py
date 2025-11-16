import os
import json
import base64
import hashlib
import sys


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s) if s else b""

def pbkdf2_key(passphrase: str, salt: bytes, length: int = 16) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100000)[:length]

def keystream(key: bytes, nonce: bytes, label: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        blk = hashlib.sha256(key + nonce + label.encode() + counter.to_bytes(4, "big")).digest()
        out += blk
        counter += 1
    return out[:length]

# ----------------------
# EKSMC: Encryption
# ----------------------
def encrypt(plaintext: str, passphrase: str) -> dict:
    salt = os.urandom(16)
    key = pbkdf2_key(passphrase, salt)

    # 1) remove spaces, record their positions (positions relative to compact)
    space_positions = []
    compact_chars = []
    for ch in plaintext:
        if ch == " ":
            space_positions.append(len(compact_chars))
        else:
            compact_chars.append(ch)
    compact_len = len(compact_chars)

    # 2) flags and case_flags
    # flags: 1 = alphabetic, 0 = non-alpha
    # case_flags: 1 = uppercase, 0 = lowercase, 2 = non-letter
    flags = [1 if c.isalpha() else 0 for c in compact_chars]
    case_flags = []
    for c in compact_chars:
        if c.isalpha():
            case_flags.append(1 if c.isupper() else 0)
        else:
            case_flags.append(2)

    flag_bytes = bytes(flags)                 # length = compact_len
    case_bytes = bytes(case_flags)            # length = compact_len

    # 3) keyed substitution (output as bytes)
    substituted = []
    for i, ch in enumerate(compact_chars):
        k = key[i % len(key)]
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            val = ord(ch) - base
            newv = (val + (k % 26)) % 26
            substituted.append(base + newv)   # store ASCII code
        else:
            substituted.append((ord(ch) + k) % 256)

    # 4) shift-merge transposition (odd/even groups and rotate even)
    odd = substituted[0::2]
    even = substituted[1::2]

    if len(even) > 0:
        s = key[1] % len(even)
        if s != 0:
            even = even[-s:] + even[:-s]  # right rotate by s

    merged = []
    o = e = 0
    while o < len(odd) or e < len(even):
        if o < len(odd):
            merged.append(odd[o]); o += 1
        if e < len(even):
            merged.append(even[e]); e += 1

    main_bytes = bytes(merged)  # length = compact_len

    # 5) encrypt metadata (space_positions, flags, case_flags) with keystream
    nonce = os.urandom(12)

    space_bytes = ",".join(map(str, space_positions)).encode() if space_positions else b""
    ks_space = keystream(key, nonce, "space", len(space_bytes))
    space_enc = bytes([a ^ b for a, b in zip(space_bytes, ks_space)]) if space_bytes else b""

    ks_flags = keystream(key, nonce, "flags", len(flag_bytes))
    flags_enc = bytes([a ^ b for a, b in zip(flag_bytes, ks_flags)]) if flag_bytes else b""

    ks_case = keystream(key, nonce, "case", len(case_bytes))
    case_enc = bytes([a ^ b for a, b in zip(case_bytes, ks_case)]) if case_bytes else b""

    # 6) package and save to file to avoid copy problems
    package = {
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "main_cipher": b64e(main_bytes),
        "space_enc": b64e(space_enc),
        "flags_enc": b64e(flags_enc),
        "case_enc": b64e(case_enc),
        "compact_len": compact_len
    }

    with open("cipher.json", "w") as f:
        json.dump(package, f, indent=4)

    return package

# ----------------------
# EKSMC: Decryption
# ----------------------
def decrypt(package: dict, passphrase: str) -> str:
    required = ["salt","nonce","main_cipher","space_enc","flags_enc","case_enc","compact_len"]
    for r in required:
        if r not in package:
            raise ValueError(f"Missing field in package: {r}")

    salt = b64d(package["salt"])
    nonce = b64d(package["nonce"])
    main_bytes = b64d(package["main_cipher"])
    space_enc = b64d(package["space_enc"])
    flags_enc = b64d(package["flags_enc"])
    case_enc = b64d(package["case_enc"])
    compact_len = int(package["compact_len"])

    key = pbkdf2_key(passphrase, salt)

    # sanity checks
    if len(main_bytes) != compact_len:
        raise ValueError(f"main_cipher length ({len(main_bytes)}) != compact_len ({compact_len})")
    if len(flags_enc) != compact_len:
        raise ValueError(f"flags_enc length ({len(flags_enc)}) != compact_len ({compact_len})")
    if len(case_enc) != compact_len:
        raise ValueError(f"case_enc length ({len(case_enc)}) != compact_len ({compact_len})")

    # recover flags and case_flags
    ks_flags = keystream(key, nonce, "flags", compact_len)
    flag_bytes = bytes([a ^ b for a, b in zip(flags_enc, ks_flags)])
    flags = list(flag_bytes)

    ks_case = keystream(key, nonce, "case", compact_len)
    case_bytes = bytes([a ^ b for a, b in zip(case_enc, ks_case)])
    case_flags = list(case_bytes)

    # recover spaces
    ks_space = keystream(key, nonce, "space", len(space_enc)) if space_enc else b""
    space_bytes = bytes([a ^ b for a, b in zip(space_enc, ks_space)]) if space_enc else b""
    space_positions = [int(x) for x in space_bytes.decode().split(",")] if space_bytes else []

    # reverse transposition
    merged = list(main_bytes)  # list of ints
    L = len(merged)
    odd_len = (L + 1) // 2
    odd = merged[:odd_len]
    even = merged[odd_len:]

    # undo the right rotate by left-rotating
    if len(even) > 0:
        s = key[1] % len(even)
        if s != 0:
            even = even[s:] + even[:s]

    restored = []
    oi = ei = 0
    for i in range(L):
        if i % 2 == 0:
            restored.append(odd[oi]); oi += 1
        else:
            restored.append(even[ei]); ei += 1

    # reverse substitution using flags & case_flags (deterministic)
    result_chars = []
    for i, code in enumerate(restored):
        k = key[i % len(key)]
        if flags[i] == 1:
            # use explicit case_flags to determine base
            if case_flags[i] == 1:
                base = ord('A')
            elif case_flags[i] == 0:
                base = ord('a')
            else:
                # fallback: assume lowercase (shouldn't happen)
                base = ord('a')
            val = code - base
            orig = (val - (k % 26)) % 26
            result_chars.append(chr(base + orig))
        else:
            orig = (code - k) % 256
            result_chars.append(chr(orig))

    # reinsert spaces (descending order)
    for pos in sorted(space_positions, reverse=True):
        if pos < 0:
            continue
        if pos > len(result_chars):
            result_chars.append(" ")
        else:
            result_chars.insert(pos, " ")

    return "".join(result_chars)

# ----------------------
# CLI helpers
# ----------------------
def read_multiline_json_prompt():
    print("Paste JSON (multi-line allowed). End with an empty line:")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "":
            break
        lines.append(line)
    return "\n".join(lines)

# ----------------------
# Main loop
# ----------------------
def main_loop():
    while True:
        print("\n1 = Encrypt")
        print("2 = Decrypt")
        print("3 = Exit")
        choice = input("Choose: ").strip()
        if choice == "1":
            pt = input("Enter plaintext: ")
            pw = input("Enter passphrase: ")
            pkg = encrypt(pt, pw)
            print("\nCIPHERTEXT PACKAGE (also saved to cipher.json):")
            print(json.dumps(pkg))   # single-line JSON for safe copying
        elif choice == "2":
            pw = input("Enter passphrase: ")
            print("Decrypt options:")
            print(" 1) Paste JSON (multi-line allowed)")
            print(" 2) Load from cipher.json file")
            sub = input("Choose 1 or 2: ").strip()
            if sub == "1":
                js = read_multiline_json_prompt()
            elif sub == "2":
                try:
                    with open("cipher.json", "r") as f:
                        js = f.read()
                    print("Loaded cipher.json")
                except Exception as e:
                    print("Failed to open cipher.json:", e)
                    continue
            else:
                print("Invalid choice")
                continue

            try:
                pkg = json.loads(js)
            except Exception as e:
                print("Invalid JSON:", e)
                continue

            try:
                recovered = decrypt(pkg, pw)
                print("Recovered plaintext:", recovered)
            except Exception as e:
                print("Decryption failed:", e)
        elif choice == "3":
            print("Exiting.")
            break
        else:
            print("Invalid.")

if __name__ == "__main__":
    main_loop()
