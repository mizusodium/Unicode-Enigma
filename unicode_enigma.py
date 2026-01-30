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
# 恩尼格码机（Unicode 版）
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
# GUI（中文界面）
# -----------------------------
class UnicodeEnigmaGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Unicode 恩尼格码机")
        self.geometry("1100x720")
        self.minsize(980, 640)

        self.machine: Optional[UnicodeEnigma] = None
        self._last_config_sig: Optional[str] = None

        self._build_ui()

    def _config_signature(self) -> str:
        p = self.pass_var.get().strip()
        rotor_count = int(self.rotor_var.get())
        plug_pairs = int(self.plug_var.get())
        notches = int(self.notch_var.get())
        raw = f"{p}|{rotor_count}|{plug_pairs}|{notches}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _ensure_initialized(self):
        passphrase = self.pass_var.get().strip()
        if not passphrase:
            raise ValueError("请填写密钥短语。")

        rotor_count = int(self.rotor_var.get())
        plug_pairs = int(self.plug_var.get())
        notches = int(self.notch_var.get())

        if not (1 <= rotor_count <= 6):
            raise ValueError("转子数量范围：1~6。")
        if not (0 <= plug_pairs <= 5000):
            raise ValueError("插线对数范围：0~5000。")
        if not (1 <= notches <= 8):
            raise ValueError("每转子缺口数范围：1~8。")

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

    def transform_once(self):
        try:
            self._ensure_initialized()
            assert self.machine is not None
            self.machine.reset()

            src = self._get_input()
            dst = self.machine.transform(src)
            self._set_output(dst)

            self._set_status(f"转换完成：输入 {len(src)} 字符，输出 {len(dst)} 字符。")
        except Exception as e:
            messagebox.showerror("错误", str(e))
            self._set_status(f"错误：{e}")

    def swap(self):
        inp = self._get_input()
        out = self.out_text.get("1.0", "end-1c")
        self.in_text.delete("1.0", tk.END)
        self.in_text.insert("1.0", out)
        self._set_output(inp)
        self._set_status("已交换输入/输出。")

    def clear_all(self):
        self.in_text.delete("1.0", tk.END)
        self.out_text.delete("1.0", tk.END)
        self._set_status("已清空。")

    def copy_output(self):
        text = self.out_text.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("已复制输出到剪贴板。")

    def output_to_input(self):
        out = self.out_text.get("1.0", "end-1c")
        self.in_text.delete("1.0", tk.END)
        self.in_text.insert("1.0", out)
        self._set_status("已将输出写回输入。")

    def _build_ui(self):
        cfg = ttk.Frame(self, padding=12)
        cfg.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(cfg, text="密钥短语：").grid(row=0, column=0, sticky="w")
        self.pass_var = tk.StringVar(value="")
        ttk.Entry(cfg, textvariable=self.pass_var, width=42).grid(row=0, column=1, sticky="w", padx=(6, 18))

        ttk.Label(cfg, text="转子数量").grid(row=0, column=2, sticky="e")
        self.rotor_var = tk.IntVar(value=3)
        ttk.Spinbox(cfg, from_=1, to=6, textvariable=self.rotor_var, width=6).grid(row=0, column=3, sticky="w", padx=(6, 18))

        ttk.Label(cfg, text="插线对数").grid(row=0, column=4, sticky="e")
        self.plug_var = tk.IntVar(value=300)
        ttk.Spinbox(cfg, from_=0, to=5000, textvariable=self.plug_var, width=8).grid(row=0, column=5, sticky="w", padx=(6, 18))

        ttk.Label(cfg, text="每转子缺口数").grid(row=0, column=6, sticky="e")
        self.notch_var = tk.IntVar(value=2)
        ttk.Spinbox(cfg, from_=1, to=8, textvariable=self.notch_var, width=6).grid(row=0, column=7, sticky="w", padx=(6, 0))

        cfg.columnconfigure(1, weight=1)

        actions = ttk.Frame(self, padding=(12, 0, 12, 10))
        actions.pack(side=tk.TOP, fill=tk.X)

        ttk.Button(actions, text="转换 ↔", command=self.transform_once).pack(side=tk.LEFT)
        ttk.Button(actions, text="交换输入/输出", command=self.swap).pack(side=tk.LEFT, padx=10)
        ttk.Button(actions, text="输出写回输入", command=self.output_to_input).pack(side=tk.LEFT)
        ttk.Button(actions, text="复制输出", command=self.copy_output).pack(side=tk.LEFT, padx=10)
        ttk.Button(actions, text="清空", command=self.clear_all).pack(side=tk.LEFT)

        panes = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 0))

        left = ttk.Labelframe(panes, text="输入", padding=8)
        right = ttk.Labelframe(panes, text="输出", padding=8)
        panes.add(left, weight=1)
        panes.add(right, weight=1)

        self.in_text = tk.Text(left, wrap="word", undo=True)
        self.out_text = tk.Text(right, wrap="word", undo=True)

        in_scroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.in_text.yview)
        out_scroll = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.out_text.yview)
        self.in_text.configure(yscrollcommand=in_scroll.set)
        self.out_text.configure(yscrollcommand=out_scroll.set)

        self.in_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        in_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.out_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        out_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # 底部状态栏
        status = ttk.Frame(self, padding=(12, 8, 12, 10))
        status.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_var = tk.StringVar(value="就绪。")
        ttk.Label(status, textvariable=self.status_var).pack(side=tk.LEFT)

if __name__ == "__main__":
    app = UnicodeEnigmaGUI()
    app.mainloop()
