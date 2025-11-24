import os
import json
import base64
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

# ======================
# Helpers
# ======================

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

# ======================
# EKSMC Encryption (process.py-aligned)
# ======================

def encrypt(plaintext: str, passphrase: str, log_fn=None, noise_bytes: int = 8) -> dict:
    def log(msg):
        if log_fn:
            log_fn(msg)

    log("Starting encryption...")

    # Step 1
    salt = os.urandom(16)
    key = pbkdf2_key(passphrase, salt)
    log(f"Key derived: {key.hex()}")

    # Step 2
    space_positions = []
    compact_chars = []
    for ch in plaintext:
        if ch == " ":
            space_positions.append(len(compact_chars))
        else:
            compact_chars.append(ch)
    compact_len = len(compact_chars)
    log(f"Compact length: {compact_len}")

    # Step 3
    flags = [1 if c.isalpha() else 0 for c in compact_chars]
    case_flags = [1 if c.isupper() else 0 if c.islower() else 2 for c in compact_chars]

    # Step 4
    substituted = []
    for i, ch in enumerate(compact_chars):
        k = key[i % len(key)]
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            newv = (ord(ch) - base + (k % 26)) % 26
            substituted.append(base + newv)
        else:
            substituted.append((ord(ch) + k) % 256)

    # Step 5
    odd = substituted[0::2]
    even = substituted[1::2]
    s = key[1] % (len(even) if len(even) else 1)
    even_rot = right_rotate(even, s) if even else []

    merged = []
    oi = ei = 0
    while oi < len(odd) or ei < len(even_rot):
        if oi < len(odd):
            merged.append(odd[oi]); oi += 1
        if ei < len(even_rot):
            merged.append(even_rot[ei]); ei += 1
    main_bytes = bytes(merged)
    log("Shift-merge complete.")

    # Step 6
    nonce = os.urandom(12)

    space_bytes = ",".join(map(str, space_positions)).encode() if space_positions else b""
    ks_space = keystream(key, nonce, "space", len(space_bytes))
    space_enc = bytes([a ^ b for a,b in zip(space_bytes, ks_space)]) if space_bytes else b""

    flag_bytes = bytes(flags)
    ks_flags = keystream(key, nonce, "flags", len(flag_bytes))
    flags_enc = bytes([a ^ b for a,b in zip(flag_bytes, ks_flags)])

    case_bytes = bytes(case_flags)
    ks_case = keystream(key, nonce, "case", len(case_bytes))
    case_enc = bytes([a ^ b for a,b in zip(case_bytes, ks_case)])

    # Step 7 (Noise)
    noiseL_raw = os.urandom(noise_bytes)
    noiseR_raw = os.urandom(noise_bytes)

    ks_noiseL = keystream(key, nonce, "noiseL", len(noiseL_raw))
    ks_noiseR = keystream(key, nonce, "noiseR", len(noiseR_raw))

    noiseL_enc = bytes([a ^ b for a,b in zip(noiseL_raw, ks_noiseL)])
    noiseR_enc = bytes([a ^ b for a,b in zip(noiseR_raw, ks_noiseR)])

    log(f"Noise injected: {noise_bytes} bytes each side.")

    # Final package (EXACT match to process.py)
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

    log("Encryption finished.")
    return package

# ======================
# EKSMC Decryption (process.py-aligned)
# ======================

def decrypt(package: dict, passphrase: str, log_fn=None) -> str:
    def log(msg):
        if log_fn:
            log_fn(msg)

    log("Starting decryption...")

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
    log("Key re-derived.")

    compact_len = len(flags_enc)
    if len(main_bytes) != compact_len:
        raise ValueError("main length mismatch")

    # Step 3
    ks_flags = keystream(key, nonce, "flags", compact_len)
    flags = [a ^ b for a,b in zip(flags_enc, ks_flags)]

    if case_enc:
        ks_case = keystream(key, nonce, "case", compact_len)
        case_flags = [a ^ b for a,b in zip(case_enc, ks_case)]
    else:
        case_flags = [0 if f==1 else 2 for f in flags]

    # Step 4
    if space_enc:
        ks_space = keystream(key, nonce, "space", len(space_enc))
        space_bytes = bytes([a ^ b for a,b in zip(space_enc, ks_space)])
        space_positions = [int(x) for x in space_bytes.decode().split(",")] if space_bytes else []
    else:
        space_positions = []

    # Step 5 reverse transposition
    merged = list(main_bytes)
    odd_rot = merged[0::2]
    even_rot = merged[1::2]

    s = key[1] % (len(even_rot) if len(even_rot) else 1)
    even = left_rotate(even_rot, s) if even_rot else []

    restored = []
    oi = ei = 0
    while oi < len(odd_rot) or ei < len(even):
        if oi < len(odd_rot):
            restored.append(odd_rot[oi]); oi += 1
        if ei < len(even):
            restored.append(even[ei]); ei += 1

    # Step 6 reverse substitution
    result_chars = []
    for i, code in enumerate(restored):
        k = key[i % len(key)]
        if flags[i] == 1:
            base = ord("A") if case_flags[i] == 1 else ord("a")
            orig = (code - base - (k % 26)) % 26
            result_chars.append(chr(base + orig))
        else:
            result_chars.append(chr((code - k) % 256))

    # Step 7 restore spaces
    for pos in sorted(space_positions, reverse=True):
        if pos > len(result_chars):
            result_chars.append(" ")
        else:
            result_chars.insert(pos, " ")

    plaintext = "".join(result_chars)
    log("Decryption finished.")
    return plaintext

# ======================
# GUI
# ======================

class EksmcUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EKSMC - Encrypt / Decrypt")
        self.geometry("900x640")
        self.last_package = None
        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(frm)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ttk.Label(left, text="Plaintext / JSON Input:").pack(anchor=tk.W)
        self.input_text = ScrolledText(left, height=12)
        self.input_text.pack(fill=tk.BOTH, expand=False)

        controls = ttk.Frame(left)
        controls.pack(fill=tk.X, pady=(6,6))

        ttk.Label(controls, text="Passphrase:").pack(side=tk.LEFT)
        self.pass_entry = ttk.Entry(controls, show="*")
        self.pass_entry.pack(side=tk.LEFT, padx=(6,10), fill=tk.X, expand=True)

        # Noise bytes control
        ttk.Label(controls, text="Noise bytes:").pack(side=tk.LEFT, padx=(6,0))
        self.noise_spin = tk.Spinbox(controls, from_=0, to=255, width=5)
        self.noise_spin.delete(0, "end")
        self.noise_spin.insert(0, "8")
        self.noise_spin.pack(side=tk.LEFT, padx=(4,10))

        btn_frame = ttk.Frame(controls)
        btn_frame.pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Encrypt → JSON", command=self._on_encrypt).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Decrypt JSON → Text", command=self._on_decrypt).pack(side=tk.LEFT, padx=4)

        file_ops = ttk.Frame(left)
        file_ops.pack(fill=tk.X)
        ttk.Button(file_ops, text="Load JSON from file", command=self._load_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(file_ops, text="Save last JSON to file", command=self._save_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(file_ops, text="Copy output", command=self._copy_output).pack(side=tk.RIGHT, padx=4)

        ttk.Label(frm, text="Output:").pack(anchor=tk.W, padx=(12,0))
        self.output_text = ScrolledText(frm, height=12)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=(12,0))

        ttk.Label(frm, text="Log:").pack(anchor=tk.W, padx=(12,0), pady=(6,0))
        self.log_text = ScrolledText(frm, height=8, foreground="#004400")
        self.log_text.pack(fill=tk.BOTH, expand=False, padx=(12,0), pady=(0,8))

    def _log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def _on_encrypt(self):
        pt = self.input_text.get("1.0", tk.END).rstrip("\n")
        pw = self.pass_entry.get()
        if not pw:
            messagebox.showwarning("Passphrase required", "Please enter a passphrase.")
            return
        # read noise bytes from spinbox
        try:
            nb = int(self.noise_spin.get())
            if nb < 0:
                raise ValueError()
        except Exception:
            messagebox.showwarning("Invalid noise", "Noise bytes must be a non-negative integer.")
            return
        try:
            pkg = encrypt(pt, pw, log_fn=self._log, noise_bytes=nb)
            self.last_package = pkg
            # show in output
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, json.dumps(pkg, indent=4))
            # write to cipher.json in current working directory
            try:
                with open("cipher.json", "w", encoding="utf-8") as f:
                    json.dump(pkg, f, indent=4)
                self._log("Encryption done. Saved to cipher.json")
                messagebox.showinfo("Saved", "Encrypted package saved to cipher.json")
            except Exception as fs_err:
                self._log("Encryption done. Failed to save cipher.json: " + str(fs_err))
                messagebox.showwarning("Save failed", f"Encrypted package created but failed to save cipher.json: {fs_err}")
        except Exception as e:
            self._log("Error: " + str(e))
            messagebox.showerror("Encryption Error", str(e))

    def _on_decrypt(self):
        jtext = self.input_text.get("1.0", tk.END).strip()
        pw = self.pass_entry.get()
        if not pw:
            messagebox.showwarning("Passphrase required", "Please enter a passphrase.")
            return
        try:
            pkg = json.loads(jtext)
        except Exception as e:
            self._log("Invalid JSON.")
            messagebox.showerror("Invalid JSON", str(e))
            return
        try:
            pt = decrypt(pkg, pw, log_fn=self._log)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, pt)
            self._log("Decryption done.")
        except Exception as e:
            self._log("Decryption error: " + str(e))
            messagebox.showerror("Decryption Error", str(e))

    def _load_file(self):
        path = filedialog.askopenfilename(title="Open JSON package",
                                          filetypes=[("JSON files","*.json"),("All files","*")])
        if not path:
            return
        try:
            with open(path,"r",encoding="utf-8") as f:
                content = f.read()
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert(tk.END, content)
            self._log(f"Loaded file: {path}")
        except Exception as e:
            self._log("Load error.")
            messagebox.showerror("Load Error", str(e))

    def _save_file(self):
        if not self.last_package:
            messagebox.showinfo("Nothing to save", "No package available.")
            return
        path = filedialog.asksaveasfilename(title="Save JSON package",
                                            defaultextension=".json",
                                            filetypes=[("JSON files","*.json"),("All files","*")])
        if not path:
            return
        try:
            with open(path,"w",encoding="utf-8") as f:
                json.dump(self.last_package, f, indent=4)
            self._log(f"Saved to: {path}")
        except Exception as e:
            self._log("Save error.")
            messagebox.showerror("Save Error", str(e))

    def _copy_output(self):
        out = self.output_text.get("1.0", tk.END).strip()
        if out:
            self.clipboard_clear()
            self.clipboard_append(out)
            self._log("Output copied to clipboard.")

if __name__ == "__main__":
    app = EksmcUI()
    app.mainloop()
