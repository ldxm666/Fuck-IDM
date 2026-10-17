#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IDM 文案溯源 - 注册表值(REG_NONE/REG_BINARY hex + REG_SZ) 解码后再搜文案.

Lead 已实测: HKCU\\Software\\DownloadManager 的值大量以 **REG_NONE + hex** 存储
(如 LocalPathW = 43003A00... = UTF-16 的 "C:")，所以 `reg query /s` 的明文 grep
天然搜不到 —— 必须 hex -> bytes -> UTF-16LE 解码.

用法:
  python reg_decode_probe2.py --reg <file.reg...> --out <log> [--dump <decoded.txt>] [--needles a,b]
"""
import argparse
import os
import re
import sys

DEFAULT_NEEDLES = [
    "fake Serial Number", "registered with a fake", "Be aware that the cracked",
    "full-featured product", "purchase the full-featured", "download files with errors",
    "Serial Number", "counterfeit", "cracked", "Internet Download Manager",
]

HEXVAL = re.compile(r'^"((?:[^"\\]|\\.)*)"=(hex(?:\([0-9a-fA-F]\))?):(.*)$')
SZVAL = re.compile(r'^"((?:[^"\\]|\\.)*)"="(.*)"$')
DWORDVAL = re.compile(r'^"((?:[^"\\]|\\.)*)"=dword:([0-9a-fA-F]+)$')


def decoded_forms(b):
    """b -> list of (form_name, text). 只保留可解出的形态."""
    out = []
    for form, enc in (("utf-16", "utf-16"), ("utf-16-be", "utf-16-be")):
        try:
            t = b.decode(enc)
            if t:
                out.append((form, t))
        except Exception:
            pass
    out.append(("latin1", b.decode("latin1", "replace")))
    return out


def printable_ratio(s):
    if not s:
        return 0.0
    ok = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\r\n\t" or ord(c) > 0xA0)
    return ok / len(s)


def parse(path):
    """-> (list of (key,name,vtype,bytes), list of (key,name,vtype,text))"""
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError:
            text = raw.decode("latin1")
    lines = text.splitlines()
    bins, strs = [], []
    cur_key = None
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        i += 1
        if not s or s.startswith(";"):
            continue
        if s.startswith("["):
            cur_key = s.strip("[]")
            continue
        m = HEXVAL.match(s)
        if m:
            name, vtype, data = m.group(1), m.group(2), m.group(3)
            parts = [data[:-1] if data.endswith("\\") else data]
            while data.endswith("\\") and i < len(lines):
                nxt = lines[i].strip()
                i += 1
                parts.append(nxt[:-1] if nxt.endswith("\\") else nxt)
                data = nxt
            hexes = [h.strip() for h in "".join(parts).split(",") if h.strip()]
            try:
                b = bytes(int(h, 16) & 0xFF for h in hexes)
            except ValueError:
                continue
            bins.append((cur_key, name, vtype, b))
            continue
        m = SZVAL.match(s)
        if m:
            strs.append((cur_key, m.group(1), "REG_SZ", m.group(2).replace("\\\\", "\\")))
            continue
        m = DWORDVAL.match(s)
        if m:
            strs.append((cur_key, m.group(1), "REG_DWORD", str(int(m.group(2), 16))))
            continue
    return bins, strs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reg", nargs="+", required=True)
    ap.add_argument("--needles", default=",".join(DEFAULT_NEEDLES))
    ap.add_argument("--out", required=True)
    ap.add_argument("--dump", default=None, help="把所有可解码的 hex 值写到该文件供抽样")
    ap.add_argument("--dump-limit", type=int, default=4000)
    ap.add_argument("--bins-out", default=None, help="把所有二进制值拼接成一个 .bin 供 xor_probe 暴力搜")
    ap.add_argument("--bins-index", default=None, help="偏移->键/值名 映射表 (TSV)")
    args = ap.parse_args()
    needles = [n for n in args.needles.split(",") if n]

    for d in (os.path.dirname(os.path.abspath(args.out)),
              os.path.dirname(os.path.abspath(args.dump)) if args.dump else None):
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)

    tot_bins = tot_strs = tot_keys = 0
    readable = 0
    hits = 0
    keynames = set()
    binf = open(args.bins_out, "wb") if args.bins_out else None
    bidxf = open(args.bins_index, "w", encoding="utf-8") if args.bins_index else None
    bidx_off = 0
    with open(args.out, "w", encoding="utf-8") as out:
        dump = open(args.dump, "w", encoding="utf-8") if args.dump else None

        def w(s):
            print(s, flush=True)
            out.write(s + "\n")

        w("# 注册表解码溯源  needles=%d" % len(needles))
        for p in args.reg:
            if not os.path.isfile(p):
                w("[MISSING] %s" % p)
                continue
            bins, strs = parse(p)
            keys = set(k for (k, _, _, _) in bins) | set(k for (k, _, _, _) in strs)
            keynames |= keys
            tot_bins += len(bins)
            tot_strs += len(strs)
            tot_keys += len(keys)
            w("[%s] 键=%d 二进制值=%d 文本值=%d" % (os.path.basename(p), len(keys), len(bins), len(strs)))
            for (key, name, vtype, b) in bins:
                if binf is not None:
                    # 用 0xFF 填充使每个值的起始为偶数对齐 (不破坏 UTF-16LE 搜索)
                    if bidx_off % 2:
                        binf.write(b"\x00")
                        bidx_off += 1
                    binf.write(b)
                    if bidxf:
                        bidxf.write("%d\t%d\t%s\t%s\t%s\n" % (bidx_off, len(b), key, name, vtype))
                    bidx_off += len(b)
                forms = decoded_forms(b)
                best = None
                for form, t in forms:
                    if printable_ratio(t) >= 0.85 and len(t.strip()) >= 4:
                        best = (form, t)
                        break
                if best:
                    readable += 1
                    if dump and readable <= args.dump_limit:
                        dump.write("%s | %s | %s | %s\n" % (key, name, vtype, best[1][:400].replace("\n", "\\n")))
                for n in needles:
                    hit = False
                    for form, t in forms:
                        j = t.find(n)
                        if j >= 0:
                            hit = True
                            hits += 1
                            w("  HIT key=%s val=%s type=%s form=%s needle=%r str_off=%d bytes=%d ctx=%r"
                              % (key, name, vtype, form, n, j, len(b), t[max(0, j - 40):j + len(n) + 40]))
                            break
                    if hit:
                        break
            for (key, name, vtype, t) in strs:
                for n in needles:
                    if n in t:
                        hits += 1
                        w("  HIT key=%s val=%s type=%s needle=%r val=%r" % (key, name, vtype, n, t[:250]))
                        break
        w("# 汇总: 文件=%d 键=%d 二进制值=%d 文本值=%d 可解码(>=85%%可打印)=%d 命中=%d"
          % (len(args.reg), len(keynames), tot_bins, tot_strs, readable, hits))
        if dump:
            dump.close()
            w("# 解码抽样已写入 %s (前 %d 条)" % (args.dump, args.dump_limit))
        if binf:
            binf.close()
            w("# 二进制值拼接已写入 %s (共 %d 字节)" % (args.bins_out, bidx_off))
        if bidxf:
            bidxf.close()
            w("# 偏移索引已写入 %s" % args.bins_index)


if __name__ == "__main__":
    main()
