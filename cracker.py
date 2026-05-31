#!/usr/bin/env python3
"""Password cracker automation tool.

Supports common hash algorithms and wordlist-based cracking with optional
candidate transformations. Designed for local hash recovery from known hashes.
"""

import argparse
import concurrent.futures
import hashlib
import itertools
import os
import sys
import threading
import time
import http.server
import socketserver
import urllib.parse
import webbrowser
from html import escape

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext
except ImportError:
    tk = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")
DEFAULT_WORDLISTS = [
    os.path.join(DEFAULT_WORDLIST_DIR, "common.txt"),
    os.path.join(DEFAULT_WORDLIST_DIR, "extra.txt"),
]
HASH_LENGTH_TO_ALGORITHMS = {
    32: ["md5", "ntlm"],
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256", "sha3_256"],
    96: ["sha384"],
    128: ["sha512"],
}
LEET_TABLE = str.maketrans({
    "a": "4",
    "A": "4",
    "b": "8",
    "B": "8",
    "e": "3",
    "E": "3",
    "i": "1",
    "I": "1",
    "o": "0",
    "O": "0",
    "s": "5",
    "S": "5",
    "t": "7",
    "T": "7",
})


def normalize_input(text: str) -> str:
    return "".join(text.strip().split())


def is_hex_string(value: str) -> bool:
    return bool(value) and all(ch in "0123456789abcdefABCDEF" for ch in value)


def guess_algorithms(target: str) -> list[str]:
    if not is_hex_string(target):
        return []
    return HASH_LENGTH_TO_ALGORITHMS.get(len(target), [])


def _left_rotate(value: int, shift: int) -> int:
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))


def _md4(data: bytes) -> str:
    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    message = bytearray(data)
    orig_len_bits = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message += orig_len_bits.to_bytes(8, "little")

    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    for offset in range(0, len(message), 64):
        chunk = message[offset : offset + 64]
        X = [int.from_bytes(chunk[i : i + 4], "little") for i in range(0, 64, 4)]
        AA, BB, CC, DD = A, B, C, D

        # Round 1
        A = _left_rotate((A + F(B, C, D) + X[0]) & 0xFFFFFFFF, 3)
        D = _left_rotate((D + F(A, B, C) + X[1]) & 0xFFFFFFFF, 7)
        C = _left_rotate((C + F(D, A, B) + X[2]) & 0xFFFFFFFF, 11)
        B = _left_rotate((B + F(C, D, A) + X[3]) & 0xFFFFFFFF, 19)
        A = _left_rotate((A + F(B, C, D) + X[4]) & 0xFFFFFFFF, 3)
        D = _left_rotate((D + F(A, B, C) + X[5]) & 0xFFFFFFFF, 7)
        C = _left_rotate((C + F(D, A, B) + X[6]) & 0xFFFFFFFF, 11)
        B = _left_rotate((B + F(C, D, A) + X[7]) & 0xFFFFFFFF, 19)
        A = _left_rotate((A + F(B, C, D) + X[8]) & 0xFFFFFFFF, 3)
        D = _left_rotate((D + F(A, B, C) + X[9]) & 0xFFFFFFFF, 7)
        C = _left_rotate((C + F(D, A, B) + X[10]) & 0xFFFFFFFF, 11)
        B = _left_rotate((B + F(C, D, A) + X[11]) & 0xFFFFFFFF, 19)
        A = _left_rotate((A + F(B, C, D) + X[12]) & 0xFFFFFFFF, 3)
        D = _left_rotate((D + F(A, B, C) + X[13]) & 0xFFFFFFFF, 7)
        C = _left_rotate((C + F(D, A, B) + X[14]) & 0xFFFFFFFF, 11)
        B = _left_rotate((B + F(C, D, A) + X[15]) & 0xFFFFFFFF, 19)

        # Round 2
        A = _left_rotate((A + G(B, C, D) + X[0] + 0x5A827999) & 0xFFFFFFFF, 3)
        D = _left_rotate((D + G(A, B, C) + X[4] + 0x5A827999) & 0xFFFFFFFF, 5)
        C = _left_rotate((C + G(D, A, B) + X[8] + 0x5A827999) & 0xFFFFFFFF, 9)
        B = _left_rotate((B + G(C, D, A) + X[12] + 0x5A827999) & 0xFFFFFFFF, 13)
        A = _left_rotate((A + G(B, C, D) + X[1] + 0x5A827999) & 0xFFFFFFFF, 3)
        D = _left_rotate((D + G(A, B, C) + X[5] + 0x5A827999) & 0xFFFFFFFF, 5)
        C = _left_rotate((C + G(D, A, B) + X[9] + 0x5A827999) & 0xFFFFFFFF, 9)
        B = _left_rotate((B + G(C, D, A) + X[13] + 0x5A827999) & 0xFFFFFFFF, 13)
        A = _left_rotate((A + G(B, C, D) + X[2] + 0x5A827999) & 0xFFFFFFFF, 3)
        D = _left_rotate((D + G(A, B, C) + X[6] + 0x5A827999) & 0xFFFFFFFF, 5)
        C = _left_rotate((C + G(D, A, B) + X[10] + 0x5A827999) & 0xFFFFFFFF, 9)
        B = _left_rotate((B + G(C, D, A) + X[14] + 0x5A827999) & 0xFFFFFFFF, 13)
        A = _left_rotate((A + G(B, C, D) + X[3] + 0x5A827999) & 0xFFFFFFFF, 3)
        D = _left_rotate((D + G(A, B, C) + X[7] + 0x5A827999) & 0xFFFFFFFF, 5)
        C = _left_rotate((C + G(D, A, B) + X[11] + 0x5A827999) & 0xFFFFFFFF, 9)
        B = _left_rotate((B + G(C, D, A) + X[15] + 0x5A827999) & 0xFFFFFFFF, 13)

        # Round 3
        A = _left_rotate((A + H(B, C, D) + X[0] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        D = _left_rotate((D + H(A, B, C) + X[8] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        C = _left_rotate((C + H(D, A, B) + X[4] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        B = _left_rotate((B + H(C, D, A) + X[12] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)
        A = _left_rotate((A + H(B, C, D) + X[2] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        D = _left_rotate((D + H(A, B, C) + X[10] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        C = _left_rotate((C + H(D, A, B) + X[6] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        B = _left_rotate((B + H(C, D, A) + X[14] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)
        A = _left_rotate((A + H(B, C, D) + X[1] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        D = _left_rotate((D + H(A, B, C) + X[9] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        C = _left_rotate((C + H(D, A, B) + X[5] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        B = _left_rotate((B + H(C, D, A) + X[13] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)
        A = _left_rotate((A + H(B, C, D) + X[3] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
        D = _left_rotate((D + H(A, B, C) + X[11] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
        C = _left_rotate((C + H(D, A, B) + X[7] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
        B = _left_rotate((B + H(C, D, A) + X[15] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    return b"".join(word.to_bytes(4, "little") for word in (A, B, C, D)).hex()


def compute_hash(candidate: str, algorithm: str) -> str:
    if algorithm == "ntlm":
        return _md4(candidate.encode("utf-16le"))
    if algorithm == "sha3_256":
        return hashlib.sha3_256(candidate.encode("utf-8")).hexdigest()
    return hashlib.new(algorithm, candidate.encode("utf-8")).hexdigest()


def load_wordlist(path: str) -> list[str]:
    words = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                word = line.strip()
                if word:
                    words.append(word)
    except OSError:
        pass
    return words


def discover_wordlist_files(wordlist_dir: str) -> list[str]:
    if not os.path.isdir(wordlist_dir):
        return []
    return sorted(
        os.path.join(wordlist_dir, entry)
        for entry in os.listdir(wordlist_dir)
        if entry.lower().endswith(".txt")
    )


def load_all_candidates(paths: list[str], allow_builtin: bool, builtins: list[str]) -> list[str]:
    candidates = []
    if allow_builtin:
        for path in builtins:
            candidates.extend(load_wordlist(path))
    for path in paths:
        candidates.extend(load_wordlist(path))
    seen = set()
    deduped = []
    for word in candidates:
        if word not in seen:
            seen.add(word)
            deduped.append(word)
    return deduped


def transform_word(word: str) -> list[str]:
    variants = []
    seen = set()
    base_forms = [word, word.lower(), word.upper(), word.capitalize(), word.title(), word[::-1], word.swapcase()]
    for entry in base_forms:
        if entry and entry not in seen:
            seen.add(entry)
            variants.append(entry)

    leet = word.translate(LEET_TABLE)
    if leet and leet not in seen:
        seen.add(leet)
        variants.append(leet)

    if len(word) <= 6:
        variants.extend([
            word + "123",
            word + "2023",
            word + "!",
            word + "@",
            word + "#",
            word + "1",
            word + "12",
            word + "1234",
            word + "2024",
        ])

    return [v for v in variants if v]


def generate_candidates(words: list[str], use_rules: bool) -> list[str]:
    if not use_rules:
        return words
    candidates = []
    seen = set()
    for word in words:
        for variant in transform_word(word):
            if variant not in seen:
                seen.add(variant)
                candidates.append(variant)
    return candidates


def brute_force_candidates(max_length: int, charset: str, max_results: int = 1000000):
    if max_length < 1:
        return
    count = 0
    for length in range(1, max_length + 1):
        for item in itertools.product(charset, repeat=length):
            yield "".join(item)
            count += 1
            if count >= max_results:
                return


def load_hashes_from_file(path: str) -> list[str]:
    hashes = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                text = normalize_input(line)
                if text:
                    hashes.append(text)
    except OSError:
        pass
    return hashes


class PassGuardXApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PASSGUARD-X")
        self.root.geometry("760x620")
        self.extra_paths = []
        self.hash_file_path = ""
        self.create_widgets()

    def create_widgets(self):
        # Hacker red / dark theme colors
        BG = "#0b0b0b"
        PANEL = "#121212"
        ACCENT = "#ff3b3b"
        TEXT = "#e6e6e6"
        OUTPUT = "#00ff6a"
        BTN_BG = "#8b0000"
        BTN_ACTIVE = "#ff4d4d"

        frame = tk.Frame(self.root, bg=BG, padx=12, pady=12)
        frame.pack(fill=tk.BOTH, expand=True)

        label_style = {"bg": BG, "fg": ACCENT}
        input_style = {"bg": PANEL, "fg": TEXT, "insertbackground": TEXT}
        btn_style = {"bg": BTN_BG, "fg": TEXT, "activebackground": BTN_ACTIVE}

        tk.Label(frame, text="Hash input (single or one per line):", **label_style).grid(row=0, column=0, sticky="w")
        self.hash_input = scrolledtext.ScrolledText(frame, height=6, width=88, **input_style)
        self.hash_input.grid(row=1, column=0, columnspan=4, pady=(0, 10), sticky="nsew")

        tk.Button(frame, text="Load hash file", command=self.load_hash_file, **btn_style).grid(row=2, column=0, sticky="w")
        self.hash_file_label = tk.Label(frame, text="No file selected", anchor="w", **label_style)
        self.hash_file_label.grid(row=2, column=1, columnspan=3, sticky="w")

        self.algorithm_var = tk.StringVar(value="auto")
        tk.Label(frame, text="Algorithm:", **label_style).grid(row=3, column=0, sticky="w", pady=(10, 0))
        tk.OptionMenu(frame, self.algorithm_var, "auto", "md5", "sha1", "sha224", "sha256", "sha3_256", "sha384", "sha512", "ntlm").grid(row=3, column=1, sticky="w", pady=(10, 0))

        self.use_builtin_var = tk.BooleanVar(value=True)
        tk.Checkbutton(frame, text="Use built-in wordlists", variable=self.use_builtin_var, bg=BG, fg=TEXT, selectcolor=BG).grid(row=3, column=2, sticky="w", pady=(10, 0))

        self.use_rules_var = tk.BooleanVar(value=True)
        tk.Checkbutton(frame, text="Apply candidate transformation rules", variable=self.use_rules_var, bg=BG, fg=TEXT, selectcolor=BG).grid(row=3, column=3, sticky="w", pady=(10, 0))

        tk.Label(frame, text="Additional wordlists:", **label_style).grid(row=4, column=0, sticky="w", pady=(10, 0))
        self.wordlist_label = tk.Label(frame, text="(none selected)", anchor="w", **label_style)
        self.wordlist_label.grid(row=4, column=1, columnspan=3, sticky="w", pady=(10, 0))

        tk.Button(frame, text="Add wordlist file", command=self.add_wordlist, **btn_style).grid(row=5, column=0, sticky="w")
        tk.Button(frame, text="Clear wordlists", command=self.clear_wordlists, **btn_style).grid(row=5, column=1, sticky="w")

        tk.Button(frame, text="Crack Passwords", command=self.start_crack, width=18, **btn_style).grid(row=6, column=0, pady=(14, 0), sticky="w")
        tk.Button(frame, text="Copy result", command=self.copy_result, width=14, **btn_style).grid(row=6, column=1, pady=(14, 0), sticky="w")

        self.status_label = tk.Label(frame, text="Ready.", anchor="w", **label_style)
        self.status_label.grid(row=6, column=2, columnspan=2, sticky="w", pady=(14, 0))

        self.output_text = scrolledtext.ScrolledText(frame, height=12, width=88, state="disabled", bg="#000000", fg=OUTPUT)
        self.output_text.grid(row=7, column=0, columnspan=4, pady=(10, 0), sticky="nsew")

        frame.grid_rowconfigure(7, weight=1)
        frame.grid_columnconfigure(3, weight=1)

    def load_hash_file(self):
        path = filedialog.askopenfilename(title="Select hash file", filetypes=[("Text files", "*.txt"), ("All files", "*")])
        if path:
            self.hash_file_path = path
            self.hash_file_label.config(text=os.path.basename(path))

    def add_wordlist(self):
        path = filedialog.askopenfilename(title="Select wordlist file", filetypes=[("Text files", "*.txt"), ("All files", "*")])
        if path:
            self.extra_paths.append(path)
            self.update_wordlist_label()

    def clear_wordlists(self):
        self.extra_paths = []
        self.update_wordlist_label()

    def update_wordlist_label(self):
        if self.extra_paths:
            display = ", ".join(os.path.basename(p) for p in self.extra_paths)
        else:
            display = "(none selected)"
        self.wordlist_label.config(text=display)

    def start_crack(self):
        hashes = self.hash_input.get("1.0", tk.END).strip().splitlines()
        hashes = [normalize_input(line) for line in hashes if normalize_input(line)]
        if self.hash_file_path:
            hashes.extend(load_hashes_from_file(self.hash_file_path))

        if not hashes:
            messagebox.showwarning("Input required", "Please paste a hash or load a hash file.")
            return

        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")
        self.status_label.config(text="Preparing cracking job...")

        thread = threading.Thread(target=self.run_crack, args=(hashes,))
        thread.daemon = True
        thread.start()

    def run_crack(self, hashes):
        builtins = DEFAULT_WORDLISTS if self.use_builtin_var.get() else []
        extra_paths = list(self.extra_paths)
        auto_paths = discover_wordlist_files(DEFAULT_WORDLIST_DIR)
        candidate_words = load_all_candidates(extra_paths + auto_paths, allow_builtin=self.use_builtin_var.get(), builtins=builtins)

        if not candidate_words:
            self.append_output("ERROR: No candidate words loaded. Add wordlists or enable built-in wordlists.\n")
            self.update_status("No candidate words available.")
            return

        candidates = generate_candidates(candidate_words, use_rules=self.use_rules_var.get())
        self.append_output(f"Loaded {len(candidate_words)} base words, {len(candidates)} candidate variants.\n")
        self.update_status(f"Cracking {len(hashes)} hash(es)...")

        for target in hashes:
            algorithms = [self.algorithm_var.get()] if self.algorithm_var.get() != "auto" else guess_algorithms(target)
            if not algorithms:
                self.append_output(f"WARNING: Unable to guess algorithm for hash '{target}'. Use the algorithm dropdown to force one.\n")
                continue

            self.append_output(f"Cracking {target} with algorithms: {', '.join(algorithms)}\n")
            start = time.time()
            result = crack(target, algorithms, candidates, update_callback=self.progress_update)
            elapsed = time.time() - start
            if result:
                password, algorithm, details = result
                self.append_output(f"[FOUND] {target} -> {password} ({algorithm}) ({details})\n")
            else:
                self.append_output(f"[NOT FOUND] {target} after {len(candidates)} candidates.\n")
            self.append_output(f"Elapsed: {elapsed:.2f}s\n\n")

        self.update_status("Done.")

    def progress_update(self, index, total):
        self.root.after(0, lambda: self.status_label.config(text=f"Tried {index}/{total} candidates..."))

    def append_output(self, message: str):
        def write_message():
            self.output_text.config(state="normal")
            self.output_text.insert(tk.END, message)
            self.output_text.see(tk.END)
            self.output_text.config(state="disabled")

        self.root.after(0, write_message)

    def update_status(self, message: str):
        self.root.after(0, lambda: self.status_label.config(text=message))

    def copy_result(self):
        text = self.output_text.get("1.0", tk.END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Copied", "Result copied to clipboard.")
        else:
            messagebox.showwarning("Nothing to copy", "There is no cracked output to copy.")


def crack(target: str, algorithms: list[str], candidates: list[str], update_callback=None) -> tuple[str, str, str] | None:
    target = normalize_input(target)
    if not is_hex_string(target) or not algorithms or not candidates:
        return None
    total = len(candidates)
    for index, candidate in enumerate(candidates, start=1):
        for algorithm in algorithms:
            if compute_hash(candidate, algorithm).lower() == target.lower():
                return candidate, algorithm, f"candidate '{candidate}' matched {algorithm}"
        if update_callback and index % 500 == 0:
            update_callback(index, total)
    return None


def crack_targets(targets: list[str], algorithms: list[str], candidates: list[str], threads: int):
    results = {}
    total = len(targets)
    if threads > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_map = {
                executor.submit(crack, target, algorithms, candidates): target for target in targets
            }
            for future in concurrent.futures.as_completed(future_map):
                target = future_map[future]
                try:
                    results[target] = future.result()
                except Exception:
                    results[target] = None
    else:
        for target in targets:
            results[target] = crack(target, algorithms, candidates)
    return results


def resolve_algorithms(target: str, forced_algorithm: str | None) -> list[str]:
    if forced_algorithm:
        return [forced_algorithm]
    return guess_algorithms(target)


def crack_cli_target(target: str, forced_algorithm: str | None, candidates: list[str]) -> tuple[str, list[str]]:
    output_lines = []
    algorithms = resolve_algorithms(target, forced_algorithm)
    if not algorithms:
        output_lines.append(f"WARNING: Unable to guess algorithm for hash '{target}'. Use --algorithm to force one.")
        return target, output_lines

    output_lines.append(f"Cracking {target} with algorithms: {', '.join(algorithms)}")
    start = time.time()
    result = crack(target, algorithms, candidates)
    elapsed = time.time() - start
    if result:
        password, algorithm, details = result
        output_lines.append(f"[FOUND] {target} -> {password} ({algorithm}) ({details})")
    else:
        output_lines.append(f"[NOT FOUND] {target} after {len(candidates)} candidates.")
    output_lines.append(f"Elapsed: {elapsed:.2f}s")
    output_lines.append("")
    return target, output_lines


def parse_args():
    parser = argparse.ArgumentParser(
        prog="passguard-x",
        description="PASSGUARD-X password hash recovery tool with GUI and CLI modes.",
        epilog=(
            "Examples:\n"
            "  passguard-x\n"
            "  passguard-x app\n"
            "  passguard-x --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5\n"
            "  passguard-x --hash-file hashes.txt --wordlist custom.txt --threads 4"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["app", "gui", "cli"],
        help="Launch mode. Use 'app' or 'gui' for the graphical app; CLI mode is selected automatically when hash options are used.",
    )
    parser.add_argument("--hash", dest="hash_value", help="Target hash value to crack.")
    parser.add_argument("--hash-file", dest="hash_file", help="Text file containing one hash per line.")
    parser.add_argument("--wordlist", dest="wordlist_files", action="append", default=[], help="Additional wordlist file path. Can be repeated.")
    parser.add_argument("--wordlist-dir", dest="wordlist_dir", default=DEFAULT_WORDLIST_DIR, help="Directory containing .txt wordlists.")
    parser.add_argument("--no-builtin", dest="no_builtin", action="store_true", help="Do not include built-in default wordlists.")
    parser.add_argument("--algorithm", dest="algorithm", choices=["md5", "sha1", "sha224", "sha256", "sha3_256", "sha384", "sha512", "ntlm"], help="Force a specific hash algorithm instead of guessing by length.")
    parser.add_argument("--no-rules", dest="use_rules", action="store_false", help="Do not apply candidate transformation rules.")
    parser.add_argument("--gui", dest="gui", action="store_true", help="Launch the graphical PASSGUARD-X application.")
    parser.add_argument("--bruteforce-length", dest="bruteforce_length", type=int, default=0, help="Add brute-force candidates up to this length using letters and digits.")
    parser.add_argument("--threads", dest="threads", type=int, default=1, help="Number of threads to use for cracking.")
    parser.add_argument("--output", dest="output_file", help="Write cracked results to a file.")
    return parser.parse_args()


def run_gui():
    if tk is not None:
        root = tk.Tk()
        PassGuardXApp(root)
        root.mainloop()
        return

    print("Tkinter is not available, launching the web app instead.")
    run_web_app()


WEB_HOST = "127.0.0.1"
WEB_PORT = 8765
WEB_PORT_ATTEMPTS = 25


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def build_html_form(result_html: str = "", status: str = "Ready.") -> str:
    algorithm_options = ["auto", "md5", "sha1", "sha224", "sha256", "sha3_256", "sha384", "sha512", "ntlm"]
    algorithm_select = "".join(
        f'<option value="{alg}">{alg}</option>' for alg in algorithm_options
    )
    return f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>PASSGUARD-X</title>
<style>
  :root {{
    --bg: #0b0b0b;
    --panel: #121212;
    --field: #050505;
    --accent: #ff3b3b;
    --accent-dark: #8b0000;
    --text: #e6e6e6;
    --muted: #a8a8a8;
    --output: #00ff6a;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    min-height: 100vh;
    background: var(--bg);
    color: var(--text);
    font-family: Arial, sans-serif;
  }}
  main {{
    width: min(980px, calc(100% - 32px));
    margin: 0 auto;
    padding: 28px 0;
  }}
  h1 {{
    color: var(--accent);
    margin: 0 0 6px;
    letter-spacing: 0;
  }}
  .status {{
    color: var(--muted);
    margin: 0 0 18px;
  }}
  form {{
    background: var(--panel);
    border: 1px solid #3a1111;
    padding: 16px;
  }}
  label {{
    display: block;
    color: var(--accent);
    margin: 0 0 12px;
  }}
  textarea, select, input[type='number'] {{
    width: 100%;
    margin-top: 6px;
    background: var(--field);
    color: var(--text);
    border: 1px solid #5f1717;
    padding: 10px;
  }}
  textarea {{ min-height: 150px; resize: vertical; }}
  .row {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
  }}
  .check {{
    color: var(--text);
  }}
  .actions {{
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 10px;
  }}
  button {{
    background: var(--accent-dark);
    color: var(--text);
    border: 1px solid var(--accent);
    padding: 10px 14px;
    cursor: pointer;
  }}
  button:hover {{ background: var(--accent); }}
  pre {{
    background: #000;
    color: var(--output);
    border: 1px solid #193d24;
    margin-top: 16px;
    padding: 14px;
    min-height: 180px;
    white-space: pre-wrap;
    overflow: auto;
  }}
</style>
</head>
<body>
<main>
<h1>PASSGUARD-X</h1>
<p class='status'>{escape(status)}</p>
<form method='POST'>
  <label>Paste hash text or one hash per line
    <textarea name='hashes' rows='6'></textarea>
  </label>
  <div class='row'>
    <label>Algorithm
      <select name='algorithm'>{algorithm_select}</select>
    </label>
    <label>Bruteforce length
      <input type='number' name='bruteforce_length' min='0' value='0'>
    </label>
  </div>
  <label class='check'><input type='checkbox' name='use_builtin' checked> Use built-in wordlists</label>
  <label class='check'><input type='checkbox' name='use_rules' checked> Apply candidate transformation rules</label>
  <div class='actions'>
    <button type='submit'>Crack Passwords</button>
    <button type='reset'>Clear</button>
  </div>
</form>
<pre>{result_html}</pre>
</main>
</body></html>"""


class PassGuardXWebHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        page = build_html_form()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(page.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(page.encode('utf-8'))

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='ignore')
        form = urllib.parse.parse_qs(body)
        hashes = form.get('hashes', [''])[0].strip().splitlines()
        hashes = [normalize_input(h) for h in hashes if normalize_input(h)]
        algorithm = form.get('algorithm', ['auto'])[0]
        use_builtin = 'use_builtin' in form
        use_rules = 'use_rules' in form
        bruteforce_length = int(form.get('bruteforce_length', ['0'])[0] or 0)

        if not hashes:
            page = build_html_form(result_html='No hash input provided.', status='Error')
            self.respond(page)
            return

        builtins = DEFAULT_WORDLISTS if use_builtin else []
        extra_paths = []
        auto_paths = discover_wordlist_files(DEFAULT_WORDLIST_DIR)
        candidate_words = load_all_candidates(extra_paths + auto_paths, allow_builtin=use_builtin, builtins=builtins)
        if bruteforce_length > 0:
            bf_charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
            candidate_words.extend(list(brute_force_candidates(bruteforce_length, bf_charset, max_results=2000000)))
        candidates = generate_candidates(candidate_words, use_rules=use_rules)

        output_lines = [f'Loaded {len(candidate_words)} base words, {len(candidates)} candidate variants.', '']
        for target in hashes:
            algorithms = [algorithm] if algorithm != 'auto' else guess_algorithms(target)
            if not algorithms:
                output_lines.append(f"WARNING: Unable to guess algorithm for hash '{target}'. Use a specific algorithm.")
                continue
            output_lines.append(f"Cracking {target} with algorithms: {', '.join(algorithms)}")
            start = time.time()
            result = crack(target, algorithms, candidates)
            elapsed = time.time() - start
            if result:
                password, alg, details = result
                output_lines.append(f"[FOUND] {target} -> {password} ({alg}) ({details})")
            else:
                output_lines.append(f"[NOT FOUND] {target} after {len(candidates)} candidates.")
            output_lines.append(f"Elapsed: {elapsed:.2f}s")
            output_lines.append('')
        page = build_html_form(result_html=escape('\n'.join(output_lines)), status='Done')
        self.respond(page)

    def respond(self, page: str):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(page.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(page.encode('utf-8'))

    def log_message(self, format, *args):
        return


def run_web_app():
    httpd = None
    selected_port = None
    for port in range(WEB_PORT, WEB_PORT + WEB_PORT_ATTEMPTS):
        try:
            httpd = ReusableTCPServer((WEB_HOST, port), PassGuardXWebHandler)
            selected_port = port
            break
        except OSError as exc:
            if exc.errno != 98:
                raise

    if httpd is None or selected_port is None:
        print(f"ERROR: No free local port found from {WEB_PORT} to {WEB_PORT + WEB_PORT_ATTEMPTS - 1}.", file=sys.stderr)
        sys.exit(1)

    url = f'http://{WEB_HOST}:{selected_port}'
    if selected_port != WEB_PORT:
        print(f'Port {WEB_PORT} is already in use; using {selected_port} instead.')

    with httpd:
        print(f'PASSGUARD-X web app running at {url}')
        webbrowser.open(url)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print('\nShutting down web app.')


def main():
    args = parse_args()

    if args.mode in ("app", "gui") or args.gui or (args.mode != "cli" and not args.hash_value and not args.hash_file):
        run_gui()
        return

    if args.mode == "cli" and not args.hash_value and not args.hash_file:
        print("ERROR: CLI mode requires --hash or --hash-file. Use 'passguard-x --help' for examples.", file=sys.stderr)
        sys.exit(1)

    hash_targets = []
    if args.hash_value:
        hash_targets.append(normalize_input(args.hash_value))
    if args.hash_file:
        hash_targets.extend(load_hashes_from_file(args.hash_file))

    hash_targets = [h for h in hash_targets if h]
    if not hash_targets:
        print("ERROR: No valid hashes found.")
        sys.exit(1)

    builtins = DEFAULT_WORDLISTS if not args.no_builtin else []
    extra_paths = list(args.wordlist_files)
    auto_paths = discover_wordlist_files(args.wordlist_dir)
    candidate_words = load_all_candidates(extra_paths + auto_paths, allow_builtin=not args.no_builtin, builtins=builtins)

    if args.bruteforce_length > 0:
        bf_charset = "abcdefghijklmnopqrstuvwxyz0123456789"
        brute_candidates = list(brute_force_candidates(args.bruteforce_length, bf_charset, max_results=2000000))
        candidate_words.extend(brute_candidates)

    if not candidate_words:
        print("ERROR: No candidate words loaded. Add wordlists or enable built-in wordlists.")
        sys.exit(1)

    candidates = generate_candidates(candidate_words, use_rules=args.use_rules)
    threads = max(1, args.threads)
    output_lines = [
        f"Loaded {len(candidate_words)} base words, {len(candidates)} candidate variants.",
        f"Preparing to crack {len(hash_targets)} hash(es) using {threads} thread(s).",
        "",
    ]

    if threads > 1 and len(hash_targets) > 1:
        results_by_index = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_map = {
                executor.submit(crack_cli_target, target, args.algorithm, candidates): index
                for index, target in enumerate(hash_targets)
            }
            for future in concurrent.futures.as_completed(future_map):
                index = future_map[future]
                _, target_lines = future.result()
                results_by_index[index] = target_lines
        for index in range(len(hash_targets)):
            output_lines.extend(results_by_index.get(index, []))
    else:
        for target in hash_targets:
            _, target_lines = crack_cli_target(target, args.algorithm, candidates)
            output_lines.extend(target_lines)

    output_text = "\n".join(output_lines)
    print(output_text)

    if args.output_file:
        try:
            with open(args.output_file, "w", encoding="utf-8") as handle:
                handle.write(output_text + "\n")
        except OSError as exc:
            print(f"ERROR: Unable to write output file '{args.output_file}': {exc}", file=sys.stderr)
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
