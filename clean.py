"""
EKSMC - Clean single-file implementation with a simple Tkinter UI

How to run:
    python eksmc_tkinter_ui.py

Features:
 - Encrypt / Decrypt using passphrase
 - Save / Load JSON package to/from file
 - Clipboard copy for output
 - Simple log pane showing steps and errors
 - Uses PBKDF2-HMAC-SHA256 for key derivation
 - Keeps behavior compatible with the original implementation

This file is intentionally self-contained and dependency-free (uses only stdlib).
"""

import os
import json
import base64
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

# ----------------------
# Helpers
# ----------------------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s) if s else b""


def pbkdf2_key(passphrase: str, salt: bytes, length: int = 16) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 100_000)[:length]


def keystream(key: bytes, nonce: bytes, label: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        blk = hashlib.sha256(
            key + nonce + label.encode("utf-8") + counter.to_bytes(4, "big")
        ).digest()
        out += blk
        counter += 1
    return out[:length]


def right_rotate(lst, s):
    if not lst or (s % len(lst) if len(lst) else 0) == 0:
        return lst[:]
    s = s % len(lst)
    return lst[-s:] + lst[:-s]


def left_rotate(lst, s):
    if not lst or (s % len(lst) if len(lst) else 0) == 0:
        return lst[:]
    s = s % len(lst)
    return lst[s:] + lst[:s]

# ----------------------
# EKSMC: Encryption
# ----------------------

def encrypt(plaintext: str, passphrase: str, log_fn=None) -> dict:
    def log(msg):
        if log_fn:
            log_fn(msg)

    log("Starting encryption...")

    salt = os.urandom(16)
    key = pbkdf2_key(passphrase, salt)
    log(f"Derived key (hex): {key.hex()} from salt {salt.hex()}")

    # Step 2: remove spaces and record positions
    space_positions = []
    compact_chars = []
    for ch in plaintext:
        if ch == " ":
            space_positions.append(len(compact_chars))
        else:
            compact_chars.append(ch)
    compact_len = len(compact_chars)
    log(f"Removed spaces -> compact length {compact_len}")

    # Step 3: flags and case_flags
    flags = [1 if c.isalpha() else 0 for c in compact_chars]
    case_flags = [
        1 if c.isupper() else 0 if c.islower() else 2
        for c in compact_chars
    ]
    log("Flags and case flags created")

    # Step 4: keyed substitution
    substituted = []
    for i, ch in enumerate(compact_chars):
        k = key[i % len(key)]
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            val = ord(ch) - base
            newv = (val + (k % 26)) % 26
            code = base + newv
            substituted.append(code)
        else:
            code = (ord(ch) + k) % 256
            substituted.append(code)
    log("Substitution complete")

    # Step 5: Enhanced Shift-merge
    odd = substituted[0::2]
    even = substituted[1::2]
    s = key[1] % (len(even) if len(even) else 1)
    even_rot = right_rotate(even, s) if len(even) else []

    merged = []
    oi = ei = 0
    while oi < len(odd) or ei < len(even_rot):
        if oi < len(odd):
            merged.append(odd[oi])
            oi += 1
        if ei < len(even_rot):
            merged.append(even_rot[ei])
            ei += 1
    main_bytes = bytes(merged)
    log(f"Transposition complete; merged length {len(main_bytes)}")

    # Step 6: Metadata encryption
    nonce = os.urandom(12)

    space_bytes = (
        ",".join(map(str, space_positions)).encode("utf-8")
        if space_positions else b""
    )
    ks_space = (
        keystream(key, nonce, "space", len(space_bytes)) if space_bytes else b""
    )
    space_enc = (
        bytes([a ^ b for a, b in zip(space_bytes, ks_space)])
        if space_bytes else b""
    )

    flag_bytes = bytes(flags)
    ks_flags = keystream(key, nonce, "flags", len(flag_bytes)) if flag_bytes else b""
    flags_enc = bytes([a ^ b for a, b in zip(flag_bytes, ks_flags)]) if flag_bytes else b""

    case_bytes = bytes(case_flags)
    ks_case = keystream(key, nonce, "case", len(case_bytes)) if case_bytes else b""
    case_enc = bytes([a ^ b for a, b in zip(case_bytes, ks_case)]) if case_bytes else b""

    package = {
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "main_cipher": b64e(main_bytes),
        "space_enc": b64e(space_enc),
        "flags_enc": b64e(flags_enc),
        "case_enc": b64e(case_enc),
        "compact_len": compact_len,
    }

    log("Encryption finished; package created")
    return package

# ----------------------
# EKSMC: Decryption
# ----------------------

def decrypt(package: dict, passphrase: str, log_fn=None) -> str:
    def log(msg):
        if log_fn:
            log_fn(msg)

    log("Starting decryption...")

    required = [
        "salt", "nonce", "main_cipher",
        "space_enc", "flags_enc", "case_enc",
        "compact_len"
    ]
    for r in required:
        if r not in package:
            raise ValueError(f"Missing field: {r}")

    salt = b64d(package["salt"])
    nonce = b64d(package["nonce"])
    main_bytes = b64d(package["main_cipher"])
    space_enc = b64d(package["space_enc"])
    flags_enc = b64d(package["flags_enc"])
    case_enc = b64d(package["case_enc"])
    compact_len = int(package["compact_len"])

    key = pbkdf2_key(passphrase, salt)
    log(f"Re-derived key (hex): {key.hex()}")

    if len(main_bytes) != compact_len:
        raise ValueError("main_cipher length mismatch")
    if len(flags_enc) != compact_len:
        raise ValueError("flags_enc length mismatch")
    if len(case_enc) != compact_len:
        raise ValueError("case_enc length mismatch")

    ks_flags = keystream(key, nonce, "flags", compact_len) if compact_len else b""
    flag_bytes = bytes([a ^ b for a, b in zip(flags_enc, ks_flags)]) if flags_enc else b""
    flags = list(flag_bytes) if flag_bytes else [0] * compact_len

    ks_case = keystream(key, nonce, "case", compact_len) if compact_len else b""
    case_bytes = bytes([a ^ b for a, b in zip(case_enc, ks_case)]) if case_enc else b""
    case_flags = list(case_bytes) if case_bytes else [2] * compact_len

    if space_enc:
        ks_space = keystream(key, nonce, "space", len(space_enc))
        space_bytes = bytes([a ^ b for a, b in zip(space_enc, ks_space)])
        space_positions = (
            [int(x) for x in space_bytes.decode("utf-8").split(",")]
            if space_bytes else []
        )
    else:
        space_positions = []

    merged = list(main_bytes)

    odd_rot = merged[0::2]
    even_rot = merged[1::2]

    s = key[1] % (len(even_rot) if len(even_rot) else 1)
    even = left_rotate(even_rot, s) if even_rot else []

    restored = []
    oi = ei = 0
    while oi < len(odd_rot) or ei < len(even):
        if oi < len(odd_rot):
            restored.append(odd_rot[oi])
            oi += 1
        if ei < len(even):
            restored.append(even[ei])
            ei += 1

    # Reverse substitution
    result_chars = []
    for i, code in enumerate(restored):
        k = key[i % len(key)]
        if flags[i] == 1:
            if case_flags[i] == 1:
                base = ord("A")
            elif case_flags[i] == 0:
                base = ord("a")
            else:
                base = ord("a")
            val = code - base
            orig = (val - (k % 26)) % 26
            ch = chr(base + orig)
            result_chars.append(ch)
        else:
            orig = (code - k) % 256
            ch = chr(orig)
            result_chars.append(ch)

    # Reinsert spaces
    for pos in sorted(space_positions, reverse=True):
        if pos < 0:
            continue
        if pos > len(result_chars):
            result_chars.append(" ")
        else:
            result_chars.insert(pos, " ")

    plaintext = "".join(result_chars)
    log("Decryption finished; plaintext recovered")
    return plaintext

# ----------------------
# GUI
# ----------------------

class EksmcUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EKSMC - Encrypt / Decrypt")
        self.geometry("900x640")

        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        # Input / controls
        left = ttk.Frame(frm)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ttk.Label(left, text="Plaintext / JSON Input:").pack(anchor=tk.W)
        self.input_text = ScrolledText(left, height=12)
        self.input_text.pack(fill=tk.BOTH, expand=False)

        controls = ttk.Frame(left)
        controls.pack(fill=tk.X, pady=(6, 6))

        ttk.Label(controls, text="Passphrase:").pack(side=tk.LEFT)
        self.pass_entry = ttk.Entry(controls, show="*")
        self.pass_entry.pack(side=tk.LEFT, padx=(6, 10), fill=tk.X, expand=True)

        btn_frame = ttk.Frame(controls)
        btn_frame.pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Encrypt → JSON", command=self._on_encrypt).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Decrypt JSON → Text", command=self._on_decrypt).pack(side=tk.LEFT, padx=4)

        file_ops = ttk.Frame(left)
        file_ops.pack(fill=tk.X)
        ttk.Button(file_ops, text="Load JSON from file", command=self._load_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(file_ops, text="Save last JSON to file", command=self._save_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(file_ops, text="Copy output to clipboard", command=self._copy_output).pack(side=tk.RIGHT, padx=4)

        # Output area
        ttk.Label(frm, text="Output:").pack(anchor=tk.W, padx=(12, 0))
        self.output_text = ScrolledText(frm, height=12)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=(12, 0))

        # Log / diagnostics
        ttk.Label(frm, text="Log:").pack(anchor=tk.W, padx=(12, 0), pady=(6, 0))
        self.log_text = ScrolledText(frm, height=8, foreground="#004400")
        self.log_text.pack(fill=tk.BOTH, expand=False, padx=(12, 0), pady=(0, 8))

        # state
        self.last_package = None

    # UI helpers
    def _log(self, msg: str):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def _on_encrypt(self):
        pt = self.input_text.get("1.0", tk.END).rstrip("\n")
        pw = self.pass_entry.get()
        if not pw:
            messagebox.showwarning("Passphrase required", "Please enter a passphrase.")
            return
        try:
            pkg = encrypt(pt, pw, log_fn=self._log)
            self.last_package = pkg
            j = json.dumps(pkg, indent=4)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, j)
            self._log("Encryption successful; JSON placed in Output")
        except Exception as e:
            self._log(f"Encryption error: {e}")
            messagebox.showerror("Encryption Error", str(e))

    def _on_decrypt(self):
        jtext = self.input_text.get("1.0", tk.END).strip()
        pw = self.pass_entry.get()
        if not pw:
            messagebox.showwarning("Passphrase required", "Please enter a passphrase.")
            return
        if not jtext:
            messagebox.showwarning("Input required", "Please paste JSON package or load from file.")
            return
        try:
            pkg = json.loads(jtext)
        except Exception as e:
            self._log(f"Invalid JSON: {e}")
            messagebox.showerror("Invalid JSON", str(e))
            return
        try:
            pt = decrypt(pkg, pw, log_fn=self._log)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, pt)
            self._log("Decryption successful; plaintext placed in Output")
        except Exception as e:
            self._log(f"Decryption error: {e}")
            messagebox.showerror("Decryption Error", str(e))

    def _load_file(self):
        path = filedialog.askopenfilename(
            title="Open JSON package",
            filetypes=[("JSON files", "*.json"), ("All files", "*")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert(tk.END, content)
            self._log(f"Loaded file: {path}")
        except Exception as e:
            self._log(f"Failed to load file: {e}")
            messagebox.showerror("Load Error", str(e))

    def _save_file(self):
        if not self.last_package:
            messagebox.showinfo("Nothing to save", "No package available. Encrypt something first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save JSON package",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*")]
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.last_package, f, indent=4)
            self._log(f"Saved package to: {path}")
            messagebox.showinfo("Saved", f"Saved to: {path}")
        except Exception as e:
            self._log(f"Failed to save file: {e}")
            messagebox.showerror("Save Error", str(e))

    def _copy_output(self):
        out = self.output_text.get("1.0", tk.END).strip()
        if not out:
            return
        self.clipboard_clear()
        self.clipboard_append(out)
        self._log("Output copied to clipboard")


if __name__ == "__main__":
    app = EksmcUI()
    app.mainloop()
