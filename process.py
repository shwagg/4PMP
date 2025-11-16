import os
import json
import base64
import hashlib

# ================================================================
#   Utility Functions
# ================================================================

# Base64 encode/decode
def b64e(b):
    return base64.b64encode(b).decode()

def b64d(s):
    return base64.b64decode(s)

def pbkdf2_key(passphrase, salt, length=16):
    """
    Derive a 128-bit key from the passphrase using PBKDF2-HMAC-SHA256.
    Salt ensures the key is unique each time.
    """
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100000)[:length]

def keystream(key, nonce, label, length):
    """
    Creates a deterministic keystream using SHA-256(key || nonce || label || counter).
    
    label: "space" or "flags" (so keystreams differ)
    nonce: ensures keystream is unique per encryption run.
    """
    out = b""
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(
            key + nonce + label.encode() + counter.to_bytes(4, "big")
        ).digest()
        out += block
        counter += 1
    return out[:length]

# ================================================================
#   EKSMC ENCRYPTION
# ================================================================

def encrypt(plaintext, passphrase):
    print("\n====== ENCRYPTION START ======\n")

    # ------------------------------------------------------------
    # 1) Key Derivation
    # ------------------------------------------------------------
    salt = os.urandom(16)
    key = pbkdf2_key(passphrase, salt)

    print("Salt (hex):", salt.hex())
    print("128-bit Key (hex):", key.hex(), "\n")

    # ------------------------------------------------------------
    # 2) Remove spaces and record their positions
    # ------------------------------------------------------------
    space_positions = []
    compact = []

    for i, ch in enumerate(plaintext):
        if ch == " ":
            space_positions.append(len(compact))
        else:
            compact.append(ch)

    print("Compact text:", "".join(compact))
    print("Space positions:", space_positions)

    flags = [1 if c.isalpha() else 0 for c in compact]
    print("Flags:", flags, "\n")

    # ------------------------------------------------------------
    # 3) Keyed Substitution
    # ------------------------------------------------------------
    substituted = []
    shifts = []

    for i, ch in enumerate(compact):
        k = key[i % 16]

        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            val = ord(ch) - base
            shift = k % 26
            shifts.append(shift)
            new_val = (val + shift) % 26
            substituted.append(chr(base + new_val))
        else:
            shift = k
            shifts.append(shift)
            substituted.append(chr((ord(ch) + shift) % 256))

    print("Substitution shifts:", shifts)
    print("After substitution:", "".join(substituted), "\n")

    # ------------------------------------------------------------
    # 4) Shift-Merge Transposition
    # ------------------------------------------------------------
    odd = substituted[0::2]
    even = substituted[1::2]

    print("Odd group:", odd)
    print("Even group:", even)

    if len(even) > 0:
        s = key[1] % len(even)
        even = even[-s:] + even[:-s]

    print("Shifted even group:", even)

    merged = []
    o = e = 0
    while o < len(odd) or e < len(even):
        if o < len(odd):
            merged.append(odd[o])
            o += 1
        if e < len(even):
            merged.append(even[e])
            e += 1

    print("After transposition:", "".join(merged), "\n")

    main_bytes = "".join(merged).encode()

    # ------------------------------------------------------------
    # 5) Encrypt space positions & flags using keystream
    # ------------------------------------------------------------
    nonce = os.urandom(12)

    space_bytes = ",".join(map(str, space_positions)).encode()
    ks_space = keystream(key, nonce, "space", len(space_bytes))
    space_enc = bytes([a ^ b for a, b in zip(space_bytes, ks_space)])

    flag_bytes = bytes(flags)
    ks_flags = keystream(key, nonce, "flags", len(flag_bytes))
    flags_enc = bytes([a ^ b for a, b in zip(flag_bytes, ks_flags)])

    print("Space bytes:", space_bytes)
    print("Space keystream:", ks_space.hex())
    print("Encrypted space bytes:", space_enc.hex(), "\n")

    print("Flag bytes:", flag_bytes)
    print("Flag keystream:", ks_flags.hex())
    print("Encrypted flag bytes:", flags_enc.hex(), "\n")

    # ------------------------------------------------------------
    # 6) Noise injection
    # ------------------------------------------------------------
    noiseL = os.urandom(3)
    noiseR = os.urandom(3)

    print("NoiseL:", noiseL.hex())
    print("NoiseR:", noiseR.hex(), "\n")

    # ------------------------------------------------------------
    # FINAL JSON PACKAGE CIPHERTEXT
    # ------------------------------------------------------------
    package = {
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "main_cipher": b64e(main_bytes),
        "space_enc": b64e(space_enc),
        "flags_enc": b64e(flags_enc),
        "noiseL": b64e(noiseL),
        "noiseR": b64e(noiseR)
    }

    print("FINAL CIPHERTEXT PACKAGE:\n", json.dumps(package, indent=4))
    print("\n====== ENCRYPTION END ======\n")

    return package

# ================================================================
#   EKSMC DECRYPTION
# ================================================================

def decrypt(package, passphrase):
    print("\n====== DECRYPTION START ======\n")

    # ------------------------------------------------------------
    # 1) Re-derive key using the salt
    # ------------------------------------------------------------
    salt = b64d(package["salt"])
    nonce = b64d(package["nonce"])
    key = pbkdf2_key(passphrase, salt)

    print("Salt (hex):", salt.hex())
    print("128-bit Key (hex):", key.hex(), "\n")

    main_bytes = b64d(package["main_cipher"])
    space_enc = b64d(package["space_enc"])
    flags_enc = b64d(package["flags_enc"])

    # ------------------------------------------------------------
    # 2) Decrypt space bytes and flags
    # ------------------------------------------------------------
    ks_space = keystream(key, nonce, "space", len(space_enc))
    space_bytes = bytes([a ^ b for a, b in zip(space_enc, ks_space)])
    print("Decrypted space bytes:", space_bytes)

    ks_flags = keystream(key, nonce, "flags", len(flags_enc))
    flags = list(bytes([a ^ b for a, b in zip(flags_enc, ks_flags)]))
    print("Decrypted flags:", flags, "\n")

    space_positions = (
        [int(x) for x in space_bytes.decode().split(",")]
        if space_bytes else []
    )

    # ------------------------------------------------------------
    # 3) Reverse Shift-Merge transposition
    # ------------------------------------------------------------
    merged = list(main_bytes.decode())
    L = len(merged)

    odd_len = (L + 1) // 2
    even_len = L // 2

    odd_part = merged[:odd_len]
    even_part = merged[odd_len:]

    if len(even_part) > 0:
        s = key[1] % len(even_part)
        even_part = even_part[s:] + even_part[:s]

    restored = []
    oi = ei = 0
    for i in range(L):
        if i % 2 == 0:
            restored.append(odd_part[oi])
            oi += 1
        else:
            restored.append(even_part[ei])
            ei += 1

    print("After un-transpose:", "".join(restored))

    # ------------------------------------------------------------
    # 4) Reverse substitution
    # ------------------------------------------------------------
    result = []
    for i, ch in enumerate(restored):
        k = key[i % 16]

        if flags[i] == 1:
            base = ord('A') if ch.isupper() else ord('a')
            val = ord(ch) - base
            orig = (val - (k % 26)) % 26
            result.append(chr(base + orig))
        else:
            result.append(chr((ord(ch) - k) % 256))

    print("After reverse substitution:", "".join(result))

    # ------------------------------------------------------------
    # 5) Reinsert spaces
    # ------------------------------------------------------------
    result_chars = result.copy()
    for pos in sorted(space_positions):
        result_chars.insert(pos, " ")

    plaintext = "".join(result_chars)

    print("Recovered plaintext:", plaintext)
    print("\n====== DECRYPTION END ======\n")

    return plaintext

# ================================================================
#   MAIN PROGRAM
# ================================================================

print("EKSMC Encryption/Decryption Demo")
print("1 = Encrypt")
print("2 = Decrypt")
choice = input("Choose: ")

if choice == "1":
    pt = input("Enter plaintext: ")
    pw = input("Enter passphrase: ")
    encrypt(pt, pw)

elif choice == "2":
    pw = input("Enter passphrase: ")
    print("Paste the ciphertext package (JSON):")
    js = input()
    package = json.loads(js)
    decrypt(package, pw)

else:
    print("Invalid choice.")
