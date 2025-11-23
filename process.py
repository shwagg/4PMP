import os
import json
import base64
import hashlib

# ----------------------
# Helpers
# ----------------------
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

def right_rotate(lst, s):
    if not lst or (s % len(lst)) == 0:
        return lst[:]
    s = s % len(lst)
    return lst[-s:] + lst[:-s]

def left_rotate(lst, s):
    if not lst or (s % len(lst)) == 0:
        return lst[:]
    s = s % len(lst)
    return lst[s:] + lst[:s]

# ----------------------
# EKSMC: Encryption (fixed, lossless)
# ----------------------
def encrypt(plaintext: str, passphrase: str, noise_bytes: int = 8) -> dict:
    print("\n=== ENCRYPTION: Start ===\n")

    # Step 1: Key derivation
    salt = os.urandom(16)
    key = pbkdf2_key(passphrase, salt)
    print("Step 1: PBKDF2 key derived")
    print("  salt (hex):", salt.hex())
    print("  key (hex):", key.hex(), "\n")

    # Step 2: Remove spaces and record positions
    space_positions = []
    compact_chars = []
    for ch in plaintext:
        if ch == " ":
            space_positions.append(len(compact_chars))
        else:
            compact_chars.append(ch)
    compact_len = len(compact_chars)
    print("Step 2: Remove spaces")
    print("  original:", repr(plaintext))
    print("  compact:", "".join(compact_chars))
    print("  space positions:", space_positions)
    print("  compact_len:", compact_len, "\n")

    # Step 3: Flags and case_flags
    flags = [1 if c.isalpha() else 0 for c in compact_chars]
    case_flags = []
    for c in compact_chars:
        if c.isalpha():
            case_flags.append(1 if c.isupper() else 0)
        else:
            case_flags.append(2)
    print("Step 3: Flags and case_flags")
    print("  flags (1=alpha):", flags)
    print("  case_flags (1=UP,0=low,2=non-letter):", case_flags, "\n")

    # Step 4: Keyed substitution (K[i mod len(key)], letters shifted)
    substituted = []
    substituted_display = []
    for i, ch in enumerate(compact_chars):
        k = key[i % len(key)]
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            val = ord(ch) - base
            newv = (val + (k % 26)) % 26
            code = base + newv
            substituted.append(code)
            substituted_display.append(f"{chr(code)}(0x{code:02x})")
        else:
            code = (ord(ch) + k) % 256
            substituted.append(code)
            substituted_display.append(f"{code}(0x{code:02x})")
    print("Step 4: Keyed substitution")
    print("  substituted (char/hex):", substituted_display)
    print("  substituted bytes:", substituted, "\n")

    # Step 5: Enhanced Shiftmerge transposition (split, right-rotate even by s, interleave)
    odd = substituted[0::2]
    even = substituted[1::2]
    print("Step 5: Split into odd/even groups")
    print("  odd  (indices 0,2,4...):", odd)
    print("  even (indices 1,3,5...):", even)
    s = key[1] % (len(even) if len(even) > 0 else 1)
    even_rot = right_rotate(even, s) if len(even) > 0 else []
    print("  rotation s = key[1] % len(even) =", s)
    print("  even after right-rotate:", even_rot)

    # Interleave alternating: odd0, even0, odd1, even1, ...
    merged = []
    oi = ei = 0
    while oi < len(odd) or ei < len(even_rot):
        if oi < len(odd):
            merged.append(odd[oi]); oi += 1
        if ei < len(even_rot):
            merged.append(even_rot[ei]); ei += 1
    main_bytes = bytes(merged)
    print("  merged (interleaved) bytes:", list(main_bytes))
    print("  main_cipher (base64):", b64e(main_bytes), "\n")

    # Step 6: Metadata encryption (space positions, flags, case_flags) using keystreams
    nonce = os.urandom(12)
    print("Step 6: Metadata encryption")
    print("  nonce (hex):", nonce.hex())

    space_bytes = ",".join(map(str, space_positions)).encode() if space_positions else b""
    ks_space = keystream(key, nonce, "space", len(space_bytes))
    space_enc = bytes([a ^ b for a,b in zip(space_bytes, ks_space)]) if space_bytes else b""
    print("  space_bytes:", space_bytes, " -> space_enc(base64):", b64e(space_enc))

    flag_bytes = bytes(flags)
    ks_flags = keystream(key, nonce, "flags", len(flag_bytes))
    flags_enc = bytes([a ^ b for a,b in zip(flag_bytes, ks_flags)]) if flag_bytes else b""
    print("  flag_bytes:", list(flag_bytes), " -> flags_enc(base64):", b64e(flags_enc))

    case_bytes = bytes(case_flags)
    ks_case = keystream(key, nonce, "case", len(case_bytes))
    case_enc = bytes([a ^ b for a,b in zip(case_bytes, ks_case)]) if case_bytes else b""
    print("  case_bytes:", list(case_bytes), " -> case_enc(base64):", b64e(case_enc), "\n")

    # Step 7: Noise injection — final JSON fields per methodology (but we include case for correctness)
    noiseL_raw = os.urandom(noise_bytes)
    noiseR_raw = os.urandom(noise_bytes)
    ks_noiseL = keystream(key, nonce, "noiseL", len(noiseL_raw))
    ks_noiseR = keystream(key, nonce, "noiseR", len(noiseR_raw))
    noiseL_enc = bytes([a ^ b for a,b in zip(noiseL_raw, ks_noiseL)])
    noiseR_enc = bytes([a ^ b for a,b in zip(noiseR_raw, ks_noiseR)])

    print("Step 7: Noise generated and encrypted (raw hex for audit):")
    print("  noiseL_raw (hex):", noiseL_raw.hex())
    print("  noiseR_raw (hex):", noiseR_raw.hex())
    print("  noiseL_enc (base64):", b64e(noiseL_enc))
    print("  noiseR_enc (base64):", b64e(noiseR_enc), "\n")

    # Final JSON packaging
    package = {
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "main": b64e(main_bytes),
        "space": b64e(space_enc),
        "flags": b64e(flags_enc),
        "case": b64e(case_enc),
        "noiseL": b64e(noiseL_enc),
        "noiseR": b64e(noiseR_enc)
    }
    with open("cipher.json", "w") as f:
        json.dump(package, f, indent=4)

    print("Step 8: Package created (saved to cipher.json)")
    print(json.dumps(package, indent=4))

    final_b64 = base64.b64encode(json.dumps(package, indent=4).encode()).decode()
    print("\nThis is final_b64:\n" + final_b64)
    print("\n=== ENCRYPTION: End ===\n")
    return package

# ----------------------
# EKSMC: Decryption (matches Process Flow and is lossless)
# ----------------------
def decrypt(package: dict, passphrase: str) -> str:
    print("\n=== DECRYPTION: Start ===\n")

    required = ["salt","nonce","main","space","flags","noiseL","noiseR"]  
    for r in required:
        if r not in package:
            raise ValueError(f"Missing field: {r}")

    salt = b64d(package["salt"])
    nonce = b64d(package["nonce"])
    main_bytes = b64d(package["main"])
    space_enc = b64d(package["space"])
    flags_enc = b64d(package["flags"])
    noiseL_enc = b64d(package["noiseL"])
    noiseR_enc = b64d(package["noiseR"])
    case_enc = b64d(package.get("case",""))

    key = pbkdf2_key(passphrase, salt)
    print("Step 1: Re-derive key")
    print("  salt (hex):", salt.hex())
    print("  key (hex):", key.hex(), "\n")

    # Recover noise for audit
    if noiseL_enc:
        ks_noiseL = keystream(key, nonce, "noiseL", len(noiseL_enc))
        noiseL_raw = bytes([a ^ b for a,b in zip(noiseL_enc, ks_noiseL)])
        print("Recovered noiseL_raw (hex):", noiseL_raw.hex())
    else:
        print("No noiseL present")

    if noiseR_enc:
        ks_noiseR = keystream(key, nonce, "noiseR", len(noiseR_enc))
        noiseR_raw = bytes([a ^ b for a,b in zip(noiseR_enc, ks_noiseR)])
        print("Recovered noiseR_raw (hex):", noiseR_raw.hex())
    else:
        print("No noiseR present")
    print()

    # Derive compact_len from flags_enc length
    compact_len = len(flags_enc)
    print("Derived compact_len from flags_enc length:", compact_len, "\n")

    # sanity check main length
    if len(main_bytes) != compact_len:
        raise ValueError("main length mismatch: expected compact_len bytes")

    print("Step 2: main and metadata lengths OK")
    print("  main_bytes (list):", list(main_bytes))
    print("  compact_len:", compact_len, "\n")

    # Step 3: Recover flags & case_flags using keystreams
    ks_flags = keystream(key, nonce, "flags", compact_len)
    flag_bytes = bytes([a ^ b for a,b in zip(flags_enc, ks_flags)]) if flags_enc else b""
    flags = list(flag_bytes) if flag_bytes else []
    print("Step 3: Recovered flags:", flags)

    if case_enc:
        ks_case = keystream(key, nonce, "case", compact_len)
        case_bytes = bytes([a ^ b for a,b in zip(case_enc, ks_case)]) if case_enc else b""
        case_flags = list(case_bytes) if case_bytes else []
        print("Step 3: Recovered case_flags (from case field):", case_flags)
    else:
        # Fallback only if 'case' absent — this is lossy: assume lowercase for letters
        case_flags = [0 if f==1 else 2 for f in flags]
        print("Step 3: 'case' field missing; using fallback case_flags (lowercase for letters):", case_flags)
    print()

    # Step 4: Recover space positions
    if space_enc:
        ks_space = keystream(key, nonce, "space", len(space_enc))
        space_bytes = bytes([a ^ b for a,b in zip(space_enc, ks_space)])
        space_positions = [int(x) for x in space_bytes.decode().split(",")] if space_bytes else []
    else:
        space_positions = []
    print("Step 4: Recovered space_positions:", space_positions, "\n")

    # Step 5: Reverse transposition
    merged = list(main_bytes)  # list of ints
    print("Step 5: merged bytes (interleaved):", merged)

    odd_rot = merged[0::2]
    even_rot = merged[1::2]
    print("  odd_rot (from merged[0::2]):", odd_rot)
    print("  even_rot (from merged[1::2]):", even_rot)

    s = key[1] % (len(even_rot) if len(even_rot)>0 else 1)
    even = left_rotate(even_rot, s) if even_rot else []
    print("  rotation s (key[1] % len(even)) =", s)
    print("  even (after left-rotate):", even)

    restored = []
    oi = ei = 0
    while oi < len(odd_rot) or ei < len(even):
        if oi < len(odd_rot):
            restored.append(odd_rot[oi]); oi += 1
        if ei < len(even):
            restored.append(even[ei]); ei += 1
    print("  restored substituted bytes:", restored, "\n")

    # Step 6: Reverse substitution using flags & case_flags
    print("Step 6: Reverse substitution")
    result_chars = []
    for i, code in enumerate(restored):
        k = key[i % len(key)]
        if i < len(flags) and flags[i] == 1:
            if i < len(case_flags) and case_flags[i] == 1:
                base = ord('A')
            else:
                base = ord('a')
            val = code - base
            orig = (val - (k % 26)) % 26
            ch = chr(base + orig)
            result_chars.append(ch)
            print(f"  idx {i}: code=0x{code:02x} flag=1 case={case_flags[i] if i < len(case_flags) else 'NA'} -> {ch}")
        else:
            orig = (code - k) % 256
            ch = chr(orig)
            result_chars.append(ch)
            print(f"  idx {i}: code=0x{code:02x} flag=0 -> {ch}")
    print()

    # Step 7: Reinsert spaces (descending order)
    for pos in sorted(space_positions, reverse=True):
        if pos < 0:
            continue
        if pos > len(result_chars):
            result_chars.append(" ")
        else:
            result_chars.insert(pos, " ")
    plaintext = "".join(result_chars)
    print("Step 7: Reinsert spaces -> recovered plaintext:", repr(plaintext))
    print("\n=== DECRYPTION: End ===\n")
    return plaintext

# ----------------------
# CLI helpers & loop
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

def main_loop():
    while True:
        print("\n1 = Encrypt")
        print("2 = Decrypt")
        print("3 = Exit")
        choice = input("Choose: ").strip()
        if choice == "1":
            pt = input("Enter plaintext: ")
            pw = input("Enter passphrase: ")
            nb = input("Noise bytes to inject (default 8): ").strip()
            try:
                nb_int = int(nb) if nb else 8
            except:
                nb_int = 8
            pkg = encrypt(pt, pw, noise_bytes=nb_int)
            print("\nSingle-line JSON (safe to copy):")
            print(json.dumps(pkg))
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
                print("Invalid JSON:", e); continue
            try:
                recovered = decrypt(pkg, pw)
                print("Recovered plaintext:", recovered)
            except Exception as e:
                print("Decryption failed:", e)
        elif choice == "3":
            print("Exiting."); break
        else:
            print("Invalid.")

if __name__ == "__main__":
    main_loop()
