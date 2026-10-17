#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IDM 文案溯源 - 注册表 REG_NONE/REG_BINARY hex -> UTF-16LE 解码后再搜文案.

Lead 已实测: HKCU\\Software\\DownloadManager 的 LocalPathW 是 REG_NONE + hex 存储的
UTF-16 串(43003A00...), 所以 `reg query /s` 的明文 grep 天然搜不到。
本脚本用 `reg export` 得到 .reg, 解析其中的 hex 值, 做 3 种解码后搜索:
  1) 原始字节按 latin1 直读
  2) UTF-16LE 解码
  3) UTF-16BE 解码
并统计检查过的键数/值数/hex 值数。

用法:
  python reg_decode_probe.py --reg <file.reg...> [--needles "fake Serial Number,..."] --out <log>
"""
import argparse
import os
import re
import sys

DEFAULT_NEEDLES = [
    "fake Serial Number",
    "registered with a fake",
    "Be aware that the cracked",
    "full-featured product",
    "purchase the full-featured",
    "download files with errors",
    "Serial Number",
    "counterfeit",
    "cracked",
    "Internet Download Manager",
]

HEXVAL = re.compile(r'^"([^"]*)"=(hex(?:\([0-9a-fA-F]\))?):(.*)$')


def parse_reg(path):
    """-> list of (hive_key, value_name, vtype, bytes)"""
    out = []
    cur_key = None
    with open(path, "r", encoding="utf-16", errors="replace") as f:
        raw = f.read()
    if "\n" not in raw or raw.count("\x00") > 20:
        with open(path, "r", encoding="latin1", errors="replace") as f:
            raw = f.read()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("["):
            cur_key = line.strip("[]")
            continue
        m = HEXVAL.match(line)
        if not m:
            continue
        name, vtype, data = m.group(1), m.group(2), m.group(3)
        parts = [data]
        # 续行: 以 \ 结尾
        idx = 0
        lines = raw.splitlines()
        while parts[-1].rstrip().endswith("\\"):
            idx += 1
            if idx > 5000:
                break
            parts[-1] = parts[-1].rstrip()[:-1]
            nxt = lines[lines.index(line) + idx].strip() if False else None
            break
        blob = "".join(parts)
        # 去掉尾部未完成项
        hexes = [h for h in blob.split(",") if re.fullmatch(r"[0-9a-fA-F]{1,2}", h.strip())]
        try:
            b = bytes(int(h, 16) for h in hexes)
        except ValueError:
            continue
        out.append((cur_key, name, vtype, b))
    return out


def multi_line_hex(path):
    """更稳的实现: 逐行状态机, 处理 hex 值的续行."""
    vals = []
    cur_key = None
    pending = None  # (name, vtype, [hexstr...])
    with open(path, "rb") as f:
        rawb = f.read()
    # reg export 是 UTF-16LE with BOM
    try:
        text = rawb.decode("utf-16")
    except UnicodeDecodeError:
        text = rawb.decode("latin1")
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(";"):
            continue
        if s.startswith("["):
            if pending:
                vals.append(_finish(cur_key, pending))
                pending = None
            cur_key = s.strip("[]")
            continue
        if pending is not None:
            part = s[:-1] if s.endswith("\\") else s
            pending[2].append(part)
            if not s.endswith("\\"):
                vals.append(_finish(cur_key, pending))
                pending = None
            continue
        m = HEXVAL.match(s)
        if m:
            name, vtype, data = m.group(1), m.group(2), m.group(3)
            parts = []
            part = data[:-1] if data.endswith("\\") else data
            parts.append(part)
            if data.endswith("\\"):
                pending = [name, vtype, parts]
            else:
                vals.append(_finish(cur_key, [name, vtype, parts]))
    if pending:
        vals.append(_finish(cur_key, pending))
    return vals


def _finish(key, pending):
    name, vtype, parts = pending
    blob = "".join(parts)
    hexes = [h.strip() for h in blob.split(",")]
    b = b""
    ok = True
    try:
        b = bytes(int(h, 16) for h in hexes if h)
    except ValueError:
        ok = False
    return (key, name, vtype, b, ok)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reg", nargs="+", required=True)
    ap.add_argument("--needles", default=",".join(DEFAULT_NEEDLES))
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    needles = [n for n in args.needles.split(",") if n]

    d = os.path.dirname(os.path.abspath(args.out))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    n_keys = set()
    n_vals = 0
    n_hex = 0
    hits = 0
    with open(args.out, "w", encoding="utf-8") as out:
        def w(s):
            print(s, flush=True)
            out.write(s + "\n")
        w("# 注册表 hex -> UTF-16 解码溯源  needles=%d" % len(needles))
        for p in args.reg:
            if not os.path.isfile(p):
                w("[MISSING] %s" % p)
                continue
            vals = multi_line_hex(p)
            w("[%s] 值总数=%d" % (os.path.basename(p), len(vals)))
            for (key, name, vtype, b, ok) in vals:
                n_vals += 1
                if key:
                    n_keys.add(key)
                if not vtype.startswith("hex"):
                    # REG_SZ 等文本值
                    try:
                        t = b.decode("utf-16")
                    except Exception:
                        t = b.decode("latin1", "replace")
                    for n in needles:
                        if n in t:
                            hits += 1
                            w("  HIT(text) key=%s val=%s type=%s needle=%r val=%r" % (key, name, vtype, n, t[:200]))
                    continue
                n_hex += 1
                cands = []
                try:
                    cands.append(("raw", b.decode("latin1")))
                except Exception:
                    pass
                for enc in ("utf-16", "utf-16-be", "utf-16-le"):
                    try:
                        cands.append((enc, b.decode(enc)))
                    except Exception:
                        pass
                for n in needles:
                    found = False
                    for (form, t) in cands:
                        j = t.find(n)
                        if j >= 0:
                            hits += 1
                            found = True
                            off = j * (2 if form.startswith("utf-16") and form != "utf-16-le" else 1)
                            w("  HIT hex key=%s val=%s type=%s form=%s needle=%r str_off=%d bytes=%d ctx=%r"
                              % (key, name, vtype, form, n, off, len(b), t[max(0, j - 30):j + len(n) + 30]))
                            break
                    if found:
                        break
        w("# 汇总: .reg文件=%d 键=%d 值=%d hex值=%d 命中=%d" % (len(args.reg), len(n_keys), n_vals, n_hex, hits))


if __name__ == "__main__":
    main()
