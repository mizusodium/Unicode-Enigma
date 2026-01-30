#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import random
import tkinter as tk
from tkinter import ttk, messagebox
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional

# -----------------------------
# Unicode 标量值映射（排除 surrogate 区）
# -----------------------------
SURROGATE_START = 0xD800
SURROGATE_END   = 0xDFFF
SCALAR_SIZE     = 0x110000 - 0x800  # 1,112,064

def cp_to_idx(cp: int) -> int:
    if SURROGATE_START <= cp <= SURROGATE_END:
        raise ValueError(f"输入包含 surrogate 码点：U+{cp:04X}")
    if cp < SURROGATE_START:
        return cp
    return cp - 0x800

def idx_to_cp(idx: int) -> int:
    if not (0 <= idx < SCALAR_SIZE):
        raise ValueError("索引超出范围")
    if idx < SURROGATE_START:
        return idx
    return idx + 0x800

# -----------------------------
# 数论工具
# -----------------------------
def egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("无法求逆元")
    return x % m

def seed_from_passphrase(passphrase: str) -> int:
    h = hashlib.sha256(passphrase.encode("utf-8")).digest()
    return int.from_bytes(h, "big")

def pick_coprime(rng: random.Random, m: int) -> int:
    # m = 2^11 * 3 * 181
    while True:
        a = rng.randrange(2, m)
        if a % 2 == 1 and a % 3 != 0 and a % 181 != 0:
            if egcd(a, m)[0] == 1:
                return a

# -----------------------------
# 恩尼格码
# -----------------------------
@dataclass
class Rotor:
    a: int
    b: int
    a_inv: int
    ring: int
    pos: int
    notches: Tuple[int, ...]

    def step(self) -> None:
        self.pos = (self.pos + 1) % SCALAR_SIZE

    def at_notch(self) -> bool:
        return self.pos in self.notches

    def _perm(self, x: int) -> int:
        return (self.a * x + self.b) % SCALAR_SIZE

    def _perm_inv(self, y: int) -> int:
        return (self.a_inv * (y - self.b)) % SCALAR_SIZE

    def forward(self, x: int) -> int:
        m = SCALAR_SIZE
        shift = (self.pos - self.ring) % m
        x1 = (x + shift) % m
        y1 = self._perm(x1)
        return (y1 - shift) % m

    def backward(self, x: int) -> int:
        m = SCALAR_SIZE
        shift = (self.pos - self.ring) % m
        x1 = (x + shift) % m
        y1 = self._perm_inv(x1)
        return (y1 - shift) % m

class UnicodeEnigma:
    def __init__(self, passphrase: str, rotor_count: int = 3, plug_pairs: int = 300, notches_per_rotor: int = 2):
        if not passphrase:
            raise ValueError("密钥短语不能为空。")

        rng = random.Random(seed_from_passphrase(passphrase))

        self.rotors: List[Rotor] = []
        for _ in range(rotor_count):
            a = pick_coprime(rng, SCALAR_SIZE)
            b = rng.randrange(SCALAR_SIZE)
            a_inv = modinv(a, SCALAR_SIZE)
            ring = rng.randrange(SCALAR_SIZE)
            pos = rng.randrange(SCALAR_SIZE)
            notches = tuple(rng.randrange(SCALAR_SIZE) for _ in range(notches_per_rotor))
            self.rotors.append(Rotor(a=a, b=b, a_inv=a_inv, ring=ring, pos=pos, notches=notches))

        self._init_positions = [r.pos for r in self.rotors]
        self.plug = self._make_plugboard(rng, plug_pairs)

    def _make_plugboard(self, rng: random.Random, pairs: int) -> Dict[int, int]:
        plug: Dict[int, int] = {}
        used = set()
        attempts = 0
        while len(plug) // 2 < pairs and attempts < pairs * 40 + 2000:
            a = rng.randrange(SCALAR_SIZE)
            b = rng.randrange(SCALAR_SIZE)
            attempts += 1
            if a == b or a in used or b in used:
                continue
            plug[a] = b
            plug[b] = a
            used.add(a); used.add(b)
        return plug

    def reset(self) -> None:
        for r, p in zip(self.rotors, self._init_positions):
            r.pos = p

    def _plug(self, x: int) -> int:
        return self.plug.get(x, x)

    def _reflect(self, x: int) -> int:
        return x + 1 if (x % 2 == 0) else x - 1

    def _step_rotors(self) -> None:
        if not self.rotors:
            return

        right = self.rotors[-1]
        if len(self.rotors) >= 2:
            middle = self.rotors[-2]

            if middle.at_notch():
                middle.step()
                if len(self.rotors) >= 3:
                    self.rotors[-3].step()

            if right.at_notch():
                middle.step()

        right.step()

    def transform(self, text: str) -> str:
        out = []
        for ch in text:
            idx = cp_to_idx(ord(ch))

            self._step_rotors()

            x = self._plug(idx)
            for r in reversed(self.rotors):
                x = r.forward(x)

            x = self._reflect(x)

            for r in self.rotors:
                x = r.backward(x)

            x = self._plug(x)
            out.append(chr(idx_to_cp(x)))
        return "".join(out)

# -----------------------------
# GUI（多语言界面：中文/English）
# -----------------------------
I18N = {
    "zh": {
        "lang_name": "中文",
        "title": "Unicode 恩尼格码机",
        "lang": "界面语言：",
        "passphrase": "密钥短语：",
        "rotor_count": "转子数量",
        "plug_pairs": "插线对数",
        "notches": "每转子缺口数",
        "btn_transform": "转换 ↔",
        "btn_swap": "交换输入/输出",
        "btn_out2in": "输出写回输入",
        "btn_copy": "复制输出",
        "btn_clear": "清空",
        "input": "输入",
        "output": "输出",
        "ready": "就绪。",
        "done": "转换完成：输入 {in_len} 字符，输出 {out_len} 字符。",
        "swapped": "已交换输入/输出。",
        "cleared": "已清空。",
        "copied": "已复制输出到剪贴板。",
        "out2in": "已将输出写回输入。",
        "err_title": "错误",
        "err_prefix": "错误：{err}",
        "err_need_pass": "请填写密钥短语。",
        "err_rotor_range": "转子数量范围：1~6。",
        "err_plug_range": "插线对数范围：0~5000。",
        "err_notch_range": "每转子缺口数范围：1~8。",
    },
    "en": {
        "lang_name": "English",
        "title": "Unicode Enigma Machine",
        "lang": "UI Language:",
        "passphrase": "Passphrase:",
        "rotor_count": "Rotors",
        "plug_pairs": "Plug pairs",
        "notches": "Notches/rotor",
        "btn_transform": "Transform ↔",
        "btn_swap": "Swap input/output",
        "btn_out2in": "Output → Input",
        "btn_copy": "Copy output",
        "btn_clear": "Clear",
        "input": "Input",
        "output": "Output",
        "ready": "Ready.",
        "done": "Done: input {in_len} chars, output {out_len} chars.",
        "swapped": "Swapped input/output.",
        "cleared": "Cleared.",
        "copied": "Copied output to clipboard.",
        "out2in": "Wrote output back to input.",
        "err_title": "Error",
        "err_prefix": "Error: {err}",
        "err_need_pass": "Please enter a passphrase.",
        "err_rotor_range": "Rotor count must be 1~6.",
        "err_plug_range": "Plug pairs must be 0~5000.",
        "err_notch_range": "Notches per rotor must be 1~8.",
    }
}

class UnicodeEnigmaGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        # language first (so title uses it)
        self.lang_var = tk.StringVar(value="zh")

        self.geometry("1100x720")
        self.minsize(980, 640)

        self.machine: Optional[UnicodeEnigma] = None
        self._last_config_sig: Optional[str] = None

        self._build_ui()
        self.apply_language()

    def tr(self, key: str, **kwargs) -> str:
        pack = I18N.get(self.lang_var.get(), I18N["en"])
        text = pack.get(key, key)
        try:
            return text.format(**kwargs)
        except Exception:
            return text

    def _config_signature(self) -> str:
        # NOTE: language does not affect machine config
        p = self.pass_var.get().strip()
        rotor_count = int(self.rotor_var.get())
        plug_pairs = int(self.plug_var.get())
        notches = int(self.notch_var.get())
        raw = f"{p}|{rotor_count}|{plug_pairs}|{notches}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _ensure_initialized(self):
        passphrase = self.pass_var.get().strip()
        if not passphrase:
            raise ValueError(self.tr("err_need_pass"))

        rotor_count = int(self.rotor_var.get())
        plug_pairs = int(self.plug_var.get())
        notches = int(self.notch_var.get())

        if not (1 <= rotor_count <= 6):
            raise ValueError(self.tr("err_rotor_range"))
        if not (0 <= plug_pairs <= 5000):
            raise ValueError(self.tr("err_plug_range"))
        if not (1 <= notches <= 8):
            raise ValueError(self.tr("err_notch_range"))

        sig = self._config_signature()
        if self.machine is None or self._last_config_sig != sig:
            self.machine = UnicodeEnigma(
                passphrase=passphrase,
                rotor_count=rotor_count,
                plug_pairs=plug_pairs,
                notches_per_rotor=notches
            )
            self.machine.reset()
            self._last_config_sig = sig

    def _get_input(self) -> str:
        return self.in_text.get("1.0", "end-1c")

    def _set_output(self, text: str):
        self.out_text.delete("1.0", tk.END)
        self.out_text.insert("1.0", text)

    def _set_status(self, msg: str):
        self.status_var.set(msg)

    def apply_language(self):
        # window + static labels/buttons
        self.title(self.tr("title"))

        self.lang_label.configure(text=self.tr("lang"))
        # Combobox shows language display names
        self.lang_combo.configure(values=[f'{k} - {I18N[k]["lang_name"]}' for k in I18N])

        self.pass_label.configure(text=self.tr("passphrase"))
        self.rotor_label.configure(text=self.tr("rotor_count"))
        self.plug_label.configure(text=self.tr("plug_pairs"))
        self.notch_label.configure(text=self.tr("notches"))

        self.btn_transform.configure(text=self.tr("btn_transform"))
        self.btn_swap.configure(text=self.tr("btn_swap"))
        self.btn_out2in.configure(text=self.tr("btn_out2in"))
        self.btn_copy.configure(text=self.tr("btn_copy"))
        self.btn_clear.configure(text=self.tr("btn_clear"))

        self.left_frame.configure(text=self.tr("input"))
        self.right_frame.configure(text=self.tr("output"))

        # status bar: only rewrite if it is one of the known "idle" states
        if self.status_var.get() in (I18N["zh"]["ready"], I18N["en"]["ready"]):
            self.status_var.set(self.tr("ready"))

    def _on_lang_change(self, *_):
        # lang_combo value like "zh - 中文"
        raw = self.lang_combo.get().strip()
        lang = raw.split(" ", 1)[0] if raw else "en"
        if lang not in I18N:
            lang = "en"
        self.lang_var.set(lang)
        self.apply_language()

    def transform_once(self):
        try:
            self._ensure_initialized()
            assert self.machine is not None
            self.machine.reset()

            src = self._get_input()
            dst = self.machine.transform(src)
            self._set_output(dst)

            self._set_status(self.tr("done", in_len=len(src), out_len=len(dst)))
        except Exception as e:
            messagebox.showerror(self.tr("err_title"), str(e))
            self._set_status(self.tr("err_prefix", err=e))

    def swap(self):
        inp = self._get_input()
        out = self.out_text.get("1.0", "end-1c")
        self.in_text.delete("1.0", tk.END)
        self.in_text.insert("1.0", out)
        self._set_output(inp)
        self._set_status(self.tr("swapped"))

    def clear_all(self):
        self.in_text.delete("1.0", tk.END)
        self.out_text.delete("1.0", tk.END)
        self._set_status(self.tr("cleared"))

    def copy_output(self):
        text = self.out_text.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(self.tr("copied"))

    def output_to_input(self):
        out = self.out_text.get("1.0", "end-1c")
        self.in_text.delete("1.0", tk.END)
        self.in_text.insert("1.0", out)
        self._set_status(self.tr("out2in"))

    def _build_ui(self):
        cfg = ttk.Frame(self, padding=12)
        cfg.pack(side=tk.TOP, fill=tk.X)

        # row 0: passphrase + params
        self.pass_label = ttk.Label(cfg, text="")
        self.pass_label.grid(row=0, column=0, sticky="w")

        self.pass_var = tk.StringVar(value="")
        ttk.Entry(cfg, textvariable=self.pass_var, width=42).grid(row=0, column=1, sticky="w", padx=(6, 18))

        self.rotor_label = ttk.Label(cfg, text="")
        self.rotor_label.grid(row=0, column=2, sticky="e")
        self.rotor_var = tk.IntVar(value=3)
        ttk.Spinbox(cfg, from_=1, to=6, textvariable=self.rotor_var, width=6).grid(row=0, column=3, sticky="w", padx=(6, 18))

        self.plug_label = ttk.Label(cfg, text="")
        self.plug_label.grid(row=0, column=4, sticky="e")
        self.plug_var = tk.IntVar(value=300)
        ttk.Spinbox(cfg, from_=0, to=5000, textvariable=self.plug_var, width=8).grid(row=0, column=5, sticky="w", padx=(6, 18))

        self.notch_label = ttk.Label(cfg, text="")
        self.notch_label.grid(row=0, column=6, sticky="e")
        self.notch_var = tk.IntVar(value=2)
        ttk.Spinbox(cfg, from_=1, to=8, textvariable=self.notch_var, width=6).grid(row=0, column=7, sticky="w", padx=(6, 0))

        # row 1: language chooser
        self.lang_label = ttk.Label(cfg, text="")
        self.lang_label.grid(row=1, column=0, sticky="w", pady=(8, 0))

        self.lang_combo = ttk.Combobox(cfg, state="readonly", width=18)
        self.lang_combo.grid(row=1, column=1, sticky="w", padx=(6, 18), pady=(8, 0))
        self.lang_combo.set("zh - 中文")
        self.lang_combo.bind("<<ComboboxSelected>>", self._on_lang_change)

        cfg.columnconfigure(1, weight=1)

        actions = ttk.Frame(self, padding=(12, 0, 12, 10))
        actions.pack(side=tk.TOP, fill=tk.X)

        self.btn_transform = ttk.Button(actions, text="", command=self.transform_once)
        self.btn_transform.pack(side=tk.LEFT)

        self.btn_swap = ttk.Button(actions, text="", command=self.swap)
        self.btn_swap.pack(side=tk.LEFT, padx=10)

        self.btn_out2in = ttk.Button(actions, text="", command=self.output_to_input)
        self.btn_out2in.pack(side=tk.LEFT)

        self.btn_copy = ttk.Button(actions, text="", command=self.copy_output)
        self.btn_copy.pack(side=tk.LEFT, padx=10)

        self.btn_clear = ttk.Button(actions, text="", command=self.clear_all)
        self.btn_clear.pack(side=tk.LEFT)

        panes = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 0))

        self.left_frame = ttk.Labelframe(panes, text="", padding=8)
        self.right_frame = ttk.Labelframe(panes, text="", padding=8)
        panes.add(self.left_frame, weight=1)
        panes.add(self.right_frame, weight=1)

        self.in_text = tk.Text(self.left_frame, wrap="word", undo=True)
        self.out_text = tk.Text(self.right_frame, wrap="word", undo=True)

        in_scroll = ttk.Scrollbar(self.left_frame, orient=tk.VERTICAL, command=self.in_text.yview)
        out_scroll = ttk.Scrollbar(self.right_frame, orient=tk.VERTICAL, command=self.out_text.yview)
        self.in_text.configure(yscrollcommand=in_scroll.set)
        self.out_text.configure(yscrollcommand=out_scroll.set)

        self.in_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        in_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.out_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        out_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # bottom status bar
        status = ttk.Frame(self, padding=(12, 8, 12, 10))
        status.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_var = tk.StringVar(value=I18N["zh"]["ready"])
        ttk.Label(status, textvariable=self.status_var).pack(side=tk.LEFT)

if __name__ == "__main__":
    app = UnicodeEnigmaGUI()
    app.mainloop()
